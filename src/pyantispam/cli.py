"""Command Line Interface for PyAntiSpam"""

import click
import logging
from logging.handlers import RotatingFileHandler
import sys
from pathlib import Path
from typing import Optional

from .config import ConfigManager
from .email import EmailProcessor
from .filters import ListManager
from datetime import datetime


def spam_decision_filter(record):
    """Filter to only allow spam decisions logs"""
    return "Email decision:" in record.getMessage()

def setup_logging(config_manager: ConfigManager, verbose: bool = False):
    """Setup logging configuration with rotating file handlers"""

    # Step 1: Read logging config
    log_config = config_manager.get("logging", {})
    system_config = log_config.get("system", {})
    decisions_config = log_config.get("decisions", {})

    # Step 2: Determine log levels
    if verbose:
        console_level = logging.DEBUG
        file_level = logging.DEBUG
    else:
        console_level = getattr(logging, system_config.get("console_level", "INFO").upper())
        file_level = getattr(logging, system_config.get("file_level", "INFO").upper())

    # Step 3: Create log directory
    system_file_path = system_config.get("file_path", "data/logs/pyantispam.log")
    decisions_file_path = decisions_config.get("file_path", "data/logs/spam_decisions.log")
    Path(system_file_path).parent.mkdir(parents=True, exist_ok=True)
    Path(decisions_file_path).parent.mkdir(parents=True, exist_ok=True)

    # Step 4: Create formatter
    simple_formatter = logging.Formatter(
      '%(asctime)s - %(levelname)s - %(message)s',
      datefmt='%Y-%m-%d %H:%M:%S'
    )
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Step 5: Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture everything, handlers will filter

    # Step 6: Add console handler (StreamHandler)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)

    # Step 7: Add system file handler (RotatingFileHandler)
    max_size = system_config.get('max_size_mb', 10) * 1024 * 1024
    backup_count = system_config.get('backup_count', 5)
    system_file_handler = RotatingFileHandler(
        filename=system_file_path,
        maxBytes=max_size,
        backupCount=backup_count
    )
    system_file_handler.setLevel(file_level)
    system_file_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(system_file_handler)

    # Step 8: Add decisions file handler (RotatingFileHandler)
    max_size = decisions_config.get('max_size_mb', 10) * 1024 * 1024
    backup_count = decisions_config.get('backup_count', 5)
    decisions_file_handler = RotatingFileHandler(
        filename=decisions_file_path,
        maxBytes=max_size,
        backupCount=backup_count
    )
    decisions_file_handler.setLevel(file_level)
    decisions_file_handler.setFormatter(simple_formatter)
    decisions_file_handler.addFilter(spam_decision_filter)
    root_logger.addHandler(decisions_file_handler)


@click.group()
@click.option('--config', '-c', default="config.yaml", help="Configuration file path")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose logging")
@click.pass_context
def main(ctx, config: str, verbose: bool):
    """PyAntiSpam - Intelligent email spam detection and filtering"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config

    # Load configuration
    config_manager = ConfigManager(config)

    # Setup logging with configuration
    setup_logging(config_manager, verbose)

    # Store config path in context
    ctx.obj['config_path'] = config


@main.command()
@click.pass_context
def setup(ctx):
    """Interactive setup wizard for PyAntiSpam"""
    click.echo("🛠️  PyAntiSpam Setup Wizard")
    click.echo("=" * 40)

    config_path = ctx.obj['config_path']
    config_file = Path(config_path)

    # Check if config already exists
    if config_file.exists():
        if not click.confirm(f"Configuration file {config_path} already exists. Overwrite?"):
            click.echo("Setup cancelled.")
            return

    # Copy example config
    example_config = Path("config.yaml.example")
    if not example_config.exists():
        click.echo("❌ config.yaml.example not found. Please ensure it exists in the current directory.")
        return

    try:
        import shutil
        shutil.copy(example_config, config_file)
        click.echo(f"✅ Created {config_path} from template")

        # Copy .env example
        env_example = Path(".env.example")
        env_file = Path(".env")
        if env_example.exists() and not env_file.exists():
            shutil.copy(env_example, env_file)
            click.echo("✅ Created .env from template")

        click.echo()
        click.echo("📝 Next steps:")
        click.echo(f"   1. Edit {config_path} with your email account details")
        click.echo("   2. Edit .env with your API keys and passwords")
        click.echo("   3. Run 'pyantispam test-config' to validate your setup")

    except Exception as e:
        click.echo(f"❌ Error during setup: {e}")


@main.command("test-config")
@click.pass_context
def test_config(ctx):
    """Test configuration and email connections"""
    click.echo("🔧 Testing PyAntiSpam configuration...")

    try:
        config = ConfigManager(ctx.obj['config_path'])
        config.validate_config()
        click.echo("✅ Configuration validation passed")

        # Test email connections
        processor = EmailProcessor(config)
        results = processor.test_connections()

        click.echo("\n📧 Email connection tests:")
        for account, success in results.items():
            status = "✅" if success else "❌"
            click.echo(f"   {status} {account}")

        if all(results.values()):
            click.echo("\n🎉 All tests passed! PyAntiSpam is ready to use.")
        else:
            click.echo("\n⚠️  Some tests failed. Please check your configuration.")

    except Exception as e:
        click.echo(f"❌ Configuration test failed: {e}")


@main.command()
@click.option('--account', '-a', help="Specific email account to process")
@click.option('--folder', '-f', default="INBOX", help="Email folder to process")
@click.option('--dry-run', is_flag=True, help="Show what would be done without making changes")
@click.pass_context
def run(ctx, account: Optional[str], folder: str, dry_run: bool):
    """Run spam detection on configured email accounts"""
    if dry_run:
        click.echo("🔍 Running in DRY-RUN mode (no changes will be made)")

    try:
        config = ConfigManager(ctx.obj['config_path'])
        processor = EmailProcessor(config)

        if not processor.initialize_clients():
            click.echo("❌ Failed to initialize email clients")
            return

        try:
            accounts = [account] if account else processor.get_account_names()

            # First, process feedback from all accounts
            if not dry_run:
                click.echo("📚 Processing feedback from special folders...")
                feedback_results = processor.process_feedback()
                if feedback_results['total_feedback'] > 0:
                    click.echo(f"   ✅ Processed {feedback_results['total_feedback']} feedback emails")
                    click.echo(f"   📝 Learning updates applied")

            for acc in accounts:
                click.echo(f"\n📬 Processing account: {acc}")

                if dry_run:
                    click.echo("   (DRY-RUN: no actual changes made)")
                    continue

                results = processor.process_account(acc, folder)

                click.echo(f"   📊 Processed: {results['processed']} emails")
                click.echo(f"   🚨 Spam detected: {results['spam_detected']}")
                click.echo(f"   🗑️  Spam moved: {results['spam_moved']}")

                if results.get('cleanup_deleted', 0) > 0:
                    click.echo(f"   🧹 Old spam deleted: {results['cleanup_deleted']}")

                if results['errors'] > 0:
                    click.echo(f"   ⚠️  Errors: {results['errors']}")

        finally:
            processor.disconnect_all()

    except Exception as e:
        click.echo(f"❌ Error during processing: {e}")


@main.command()
@click.option('--interval', '-i', default=300, help="Check interval in seconds")
@click.pass_context
def daemon(ctx, interval: int):
    """Run PyAntiSpam in daemon mode (continuous monitoring)"""
    import time

    click.echo(f"🤖 Starting PyAntiSpam daemon (check every {interval} seconds)")
    click.echo("Press Ctrl+C to stop")

    try:
        config = ConfigManager(ctx.obj['config_path'])

        while True:
            try:
                processor = EmailProcessor(config)

                if processor.initialize_clients():
                    # Process feedback first
                    feedback_results = processor.process_feedback()
                    if feedback_results['total_feedback'] > 0:
                        click.echo(f"📚 Processed {feedback_results['total_feedback']} feedback emails")

                    # Then process new emails
                    for account in processor.get_account_names():
                        results = processor.process_account(account)
                        if results['spam_detected'] > 0:
                            click.echo(f"🚨 {account}: {results['spam_detected']} spam emails processed")

                    processor.disconnect_all()

            except Exception as e:
                click.echo(f"⚠️  Error in daemon loop: {e}")

            time.sleep(interval)

    except KeyboardInterrupt:
        click.echo("\n🛑 Daemon stopped by user")


# Whitelist/Blacklist management commands
@main.group()
def whitelist():
    """Manage whitelist (trusted senders)"""
    pass


@whitelist.command("add")
@click.argument('item')
@click.option('--type', 'item_type', type=click.Choice(['email', 'domain', 'auto']), default='auto')
@click.pass_context
def whitelist_add(ctx, item: str, item_type: str):
    """Add email or domain to whitelist"""
    try:
        list_manager = ListManager()
        list_manager.add_to_whitelist(item, item_type)
        click.echo(f"✅ Added '{item}' to whitelist")
    except Exception as e:
        click.echo(f"❌ Error: {e}")


@whitelist.command("remove")
@click.argument('item')
@click.option('--type', 'item_type', type=click.Choice(['email', 'domain', 'auto']), default='auto')
@click.pass_context
def whitelist_remove(ctx, item: str, item_type: str):
    """Remove email or domain from whitelist"""
    try:
        list_manager = ListManager()
        success = list_manager.remove_from_whitelist(item, item_type)
        if success:
            click.echo(f"✅ Removed '{item}' from whitelist")
        else:
            click.echo(f"⚠️  '{item}' was not in whitelist")
    except Exception as e:
        click.echo(f"❌ Error: {e}")


@whitelist.command("list")
@click.pass_context
def whitelist_list(ctx):
    """Show current whitelist"""
    try:
        list_manager = ListManager()
        whitelist_data = list_manager.get_whitelist()

        click.echo("📧 Whitelisted Emails:")
        for email in whitelist_data['emails']:
            click.echo(f"   {email}")

        click.echo("\n🌐 Whitelisted Domains:")
        for domain in whitelist_data['domains']:
            click.echo(f"   {domain}")

        stats = list_manager.get_stats()
        click.echo(f"\n📊 Total: {stats['whitelist_emails']} emails, {stats['whitelist_domains']} domains")

    except Exception as e:
        click.echo(f"❌ Error: {e}")


@main.group()
def blacklist():
    """Manage blacklist (blocked senders)"""
    pass


@blacklist.command("add")
@click.argument('item')
@click.option('--type', 'item_type', type=click.Choice(['email', 'domain', 'auto']), default='auto')
@click.pass_context
def blacklist_add(ctx, item: str, item_type: str):
    """Add email or domain to blacklist"""
    try:
        list_manager = ListManager()
        list_manager.add_to_blacklist(item, item_type)
        click.echo(f"✅ Added '{item}' to blacklist")
    except Exception as e:
        click.echo(f"❌ Error: {e}")


@blacklist.command("remove")
@click.argument('item')
@click.option('--type', 'item_type', type=click.Choice(['email', 'domain', 'auto']), default='auto')
@click.pass_context
def blacklist_remove(ctx, item: str, item_type: str):
    """Remove email or domain from blacklist"""
    try:
        list_manager = ListManager()
        success = list_manager.remove_from_blacklist(item, item_type)
        if success:
            click.echo(f"✅ Removed '{item}' from blacklist")
        else:
            click.echo(f"⚠️  '{item}' was not in blacklist")
    except Exception as e:
        click.echo(f"❌ Error: {e}")


@blacklist.command("list")
@click.pass_context
def blacklist_list(ctx):
    """Show current blacklist"""
    try:
        list_manager = ListManager()
        blacklist_data = list_manager.get_blacklist()

        click.echo("📧 Blacklisted Emails:")
        for email in blacklist_data['emails']:
            click.echo(f"   {email}")

        click.echo("\n🌐 Blacklisted Domains:")
        for domain in blacklist_data['domains']:
            click.echo(f"   {domain}")

        stats = list_manager.get_stats()
        click.echo(f"\n📊 Total: {stats['blacklist_emails']} emails, {stats['blacklist_domains']} domains")

    except Exception as e:
        click.echo(f"❌ Error: {e}")


@main.command()
@click.pass_context
def status(ctx):
    """Show PyAntiSpam status and statistics"""
    try:
        list_manager = ListManager()
        stats = list_manager.get_stats()

        click.echo("📊 PyAntiSpam Status")
        click.echo("=" * 20)
        click.echo(f"Whitelist: {stats['whitelist_emails']} emails, {stats['whitelist_domains']} domains")
        click.echo(f"Blacklist: {stats['blacklist_emails']} emails, {stats['blacklist_domains']} domains")

        # TODO: Add more statistics (emails processed, spam detected, etc.)

    except Exception as e:
        click.echo(f"❌ Error: {e}")


@main.command()
@click.option('--daily', is_flag=True, help="Show daily statistics breakdown")
@click.option('--days', default=7, help="Number of days for daily stats")
@click.option('--export', type=str, help="Export statistics to file")
@click.pass_context
def stats(ctx, daily: bool, days: int, export: Optional[str]):
    """Show comprehensive spam detection statistics"""
    try:
        config_file = ctx.obj.get('config', 'config.yaml')
        config_manager = ConfigManager(config_file)
        processor = EmailProcessor(config_manager)

        if export:
            processor.export_statistics(export)
            click.echo(f"📄 Statistics exported to: {export}")
            return

        if daily:
            _show_daily_stats(processor, days)
        else:
            _show_general_stats(processor)

    except Exception as e:
        click.echo(f"❌ Error: {e}")


def _show_general_stats(processor):
    """Display general statistics"""
    stats = processor.get_statistics()

    click.echo("📊 PyAntiSpam - Statistiques")
    click.echo("=" * 50)

    # Vue d'ensemble
    click.echo("\n🔍 DÉTECTION:")
    overview = stats['overview']
    click.echo(f"  📧 Emails traités      : {overview['total_emails_processed']:,}")
    click.echo(f"  🗑️  Spams détectés      : {overview['spam_detected']:,}")
    click.echo(f"  ✅ Ham détectés        : {overview['ham_detected']:,}")
    click.echo(f"  📈 Taux de spam        : {overview['spam_detection_rate']}%")

    # Méthodes de détection
    click.echo("\n🎯 MÉTHODES DE DÉTECTION:")
    methods = stats['detection_methods']
    if sum(methods.values()) > 0:
        for method, count in methods.items():
            if count > 0:
                click.echo(f"  {method:15} : {count:,}")
    else:
        click.echo("  Aucune détection enregistrée")

    # Distribution de confiance
    click.echo("\n📊 CONFIANCE:")
    conf = stats['confidence_distribution']
    total_conf = sum(conf.values())
    if total_conf > 0:
        for level, count in conf.items():
            pct = (count / total_conf) * 100
            click.echo(f"  {level:8} : {count:,} ({pct:.1f}%)")
    else:
        click.echo("  Aucune donnée de confiance")

    # Apprentissage
    click.echo("\n📚 APPRENTISSAGE:")
    learning = stats['learning']
    click.echo(f"  📝 Feedback total      : {learning['total_feedback']:,}")
    click.echo(f"  ✅ Ajouts whitelist    : {learning['whitelist_additions']:,}")
    click.echo(f"  ❌ Ajouts blacklist    : {learning['blacklist_additions']:,}")
    click.echo(f"  🤖 Échantillons ML     : {learning['ml_training_samples']:,}")
    click.echo(f"  🔄 Réentraînements ML  : {learning['ml_retraining_count']:,}")

    # Feedback par type
    feedback_types = learning['feedback_by_type']
    if sum(feedback_types.values()) > 0:
        click.echo("\n📝 FEEDBACK PAR TYPE:")
        for ftype, count in feedback_types.items():
            if count > 0:
                click.echo(f"  {ftype:12} : {count:,}")

    # Performance
    click.echo("\n⚡ PERFORMANCE:")
    perf = stats['performance']
    click.echo(f"  ⏱️  Temps moyen        : {perf['avg_processing_time']:.3f}s")
    click.echo(f"  ❗ Erreurs total       : {perf['errors_count']:,}")

    if perf['last_error_date']:
        error_date = datetime.fromisoformat(perf['last_error_date'])
        click.echo(f"  📅 Dernière erreur     : {error_date.strftime('%Y-%m-%d %H:%M:%S')}")

    # Efficacité des méthodes
    effectiveness = processor.get_detection_effectiveness()
    if 'error' not in effectiveness and any(data['count'] > 0 for data in effectiveness.values()):
        click.echo("\n📈 EFFICACITÉ DES MÉTHODES:")
        for method, data in sorted(effectiveness.items(), key=lambda x: x[1]['count'], reverse=True):
            if data['count'] > 0:
                click.echo(f"  {method:15} : {data['count']:,} détections ({data['percentage']:5.1f}%)")

    click.echo(f"\n📊 Dernière mise à jour: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def _show_daily_stats(processor, days):
    """Display daily statistics"""
    daily = processor.get_daily_statistics(days)

    click.echo(f"📅 DÉTAILS QUOTIDIENS ({days} derniers jours)")
    click.echo("=" * 50)

    for date, stats in sorted(daily.items(), reverse=True):
        if any(stats[key] > 0 for key in ['emails_processed', 'feedback_processed', 'errors']):
            click.echo(f"\n📆 {date}:")
            click.echo(f"  📧 Emails traités     : {stats['emails_processed']:,}")
            click.echo(f"  🗑️  Spams détectés     : {stats['spam_detected']:,}")
            click.echo(f"  ✅ Ham détectés       : {stats['ham_detected']:,}")
            click.echo(f"  📝 Feedback traité    : {stats['feedback_processed']:,}")
            click.echo(f"  ❗ Erreurs            : {stats['errors']:,}")

            if stats['methods_used']:
                click.echo("  🎯 Méthodes utilisées :")
                for method, count in stats['methods_used'].items():
                    click.echo(f"    {method:13} : {count:,}")


@main.command("recurring-senders")
@click.option('--spam-only', is_flag=True, help="Show only spam senders")
@click.option('--ham-only', is_flag=True, help="Show only legitimate senders")
@click.option('--threshold', '-t', default=2, help="Minimum feedback count to show")
@click.option('--limit', '-l', default=20, help="Maximum number of senders to show")
@click.pass_context
def recurring_senders(ctx, spam_only: bool, ham_only: bool, threshold: int, limit: int):
    """Show senders with recurring feedback patterns"""
    import json
    from pathlib import Path

    try:
        history_file = Path("data/sender_feedback_history.json")

        if not history_file.exists():
            click.echo("⚠️  No sender feedback history found yet.")
            click.echo("   Feedback history is created when you process emails in PYANTISPAM_* folders.")
            return

        with open(history_file, 'r', encoding='utf-8') as f:
            history = json.load(f)

        if not history:
            click.echo("⚠️  No sender feedback history found yet.")
            return

        # Filter and sort senders
        senders_data = []
        for sender_email, data in history.items():
            total_spam = data['spam_count'] + data['blacklist_count']
            total_ham = data['ham_count'] + data['whitelist_count']
            total_feedback = total_spam + total_ham

            # Apply filters
            if total_feedback < threshold:
                continue
            if spam_only and total_spam == 0:
                continue
            if ham_only and total_ham == 0:
                continue

            senders_data.append({
                'email': sender_email,
                'domain': data['sender_domain'],
                'spam': total_spam,
                'ham': total_ham,
                'total': total_feedback,
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen']
            })

        # Sort by total feedback count
        senders_data.sort(key=lambda x: x['total'], reverse=True)

        if not senders_data:
            click.echo("⚠️  No senders match the specified criteria.")
            return

        # Display results
        click.echo("🔄 EXPÉDITEURS RÉCURRENTS DANS LES FEEDBACKS")
        click.echo("=" * 80)
        click.echo(f"\nShowing top {min(limit, len(senders_data))} senders (threshold: {threshold}+ feedbacks)\n")

        # Load auto-blacklist/whitelist thresholds from config
        try:
            config = ConfigManager(ctx.obj['config_path'])
            auto_bl_threshold = config.config.get("learning", {}).get("auto_blacklist_threshold", 3)
            auto_wl_threshold = config.config.get("learning", {}).get("auto_whitelist_threshold", 3)
        except:
            auto_bl_threshold = 3
            auto_wl_threshold = 3

        for i, sender in enumerate(senders_data[:limit], 1):
            # Determine status
            status_icons = []
            if sender['spam'] >= auto_bl_threshold:
                status_icons.append("🚫 AUTO-BLACKLISTED")
            if sender['ham'] >= auto_wl_threshold:
                status_icons.append("✅ AUTO-WHITELISTED")

            status_text = " ".join(status_icons) if status_icons else ""

            click.echo(f"{i:2}. {sender['email']}")
            click.echo(f"    📊 Spam: {sender['spam']}  |  Ham: {sender['ham']}  |  Total: {sender['total']}")

            # Show domain if different from email
            if sender['domain'] and sender['domain'] not in sender['email']:
                click.echo(f"    🌐 Domain: {sender['domain']}")

            if status_text:
                click.echo(f"    {status_text}")

            # Show proximity to thresholds
            if sender['spam'] > 0 and sender['spam'] < auto_bl_threshold:
                remaining = auto_bl_threshold - sender['spam']
                click.echo(f"    ⚠️  {remaining} more spam feedback(s) until auto-blacklist")

            if sender['ham'] > 0 and sender['ham'] < auto_wl_threshold:
                remaining = auto_wl_threshold - sender['ham']
                click.echo(f"    ℹ️  {remaining} more ham feedback(s) until auto-whitelist")

            # Show dates
            from datetime import datetime
            last_seen_dt = datetime.fromtimestamp(sender['last_seen'])
            days_ago = (datetime.now() - last_seen_dt).days
            click.echo(f"    📅 Last seen: {last_seen_dt.strftime('%Y-%m-%d %H:%M')} ({days_ago} days ago)")
            click.echo()

        click.echo(f"Total senders in history: {len(history)}")
        click.echo(f"Shown: {min(limit, len(senders_data))} / {len(senders_data)} matching criteria")

        # Show summary
        total_spam_senders = sum(1 for s in senders_data if s['spam'] > 0)
        total_ham_senders = sum(1 for s in senders_data if s['ham'] > 0)
        auto_blacklisted = sum(1 for s in senders_data if s['spam'] >= auto_bl_threshold)
        auto_whitelisted = sum(1 for s in senders_data if s['ham'] >= auto_wl_threshold)

        click.echo(f"\n📈 SUMMARY:")
        click.echo(f"   Spam senders: {total_spam_senders}")
        click.echo(f"   Ham senders: {total_ham_senders}")
        click.echo(f"   Auto-blacklisted: {auto_blacklisted}")
        click.echo(f"   Auto-whitelisted: {auto_whitelisted}")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()