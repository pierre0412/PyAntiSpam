#!/usr/bin/env python3
"""Script pour afficher les statistiques PyAntiSpam"""

from src.pyantispam.email.email_processor import EmailProcessor
from src.pyantispam.config import ConfigManager
from datetime import datetime


def format_stats():
    """Affiche les statistiques formatées"""
    try:
        config = ConfigManager('config.yaml')
        processor = EmailProcessor(config)

        print("📊 PyAntiSpam - Statistiques")
        print("=" * 50)

        # Statistiques générales
        stats = processor.get_statistics()

        print("\n🔍 DÉTECTION:")
        overview = stats['overview']
        print(f"  📧 Emails traités      : {overview['total_emails_processed']:,}")
        print(f"  🗑️  Spams détectés      : {overview['spam_detected']:,}")
        print(f"  ✅ Ham détectés        : {overview['ham_detected']:,}")
        print(f"  📈 Taux de spam        : {overview['spam_detection_rate']}%")

        # Méthodes de détection
        print("\n🎯 MÉTHODES DE DÉTECTION:")
        methods = stats['detection_methods']
        for method, count in methods.items():
            if count > 0:
                print(f"  {method:15} : {count:,}")

        if sum(methods.values()) == 0:
            print("  Aucune détection enregistrée")

        # Distribution de confiance
        print("\n📊 CONFIANCE:")
        conf = stats['confidence_distribution']
        total_conf = sum(conf.values())
        if total_conf > 0:
            for level, count in conf.items():
                pct = (count / total_conf) * 100
                print(f"  {level:8} : {count:,} ({pct:.1f}%)")
        else:
            print("  Aucune donnée de confiance")

        # Apprentissage
        print("\n📚 APPRENTISSAGE:")
        learning = stats['learning']
        print(f"  📝 Feedback total      : {learning['total_feedback']:,}")
        print(f"  ✅ Ajouts whitelist    : {learning['whitelist_additions']:,}")
        print(f"  ❌ Ajouts blacklist    : {learning['blacklist_additions']:,}")
        print(f"  🤖 Échantillons ML     : {learning['ml_training_samples']:,}")
        print(f"  🔄 Réentraînements ML  : {learning['ml_retraining_count']:,}")

        # Feedback par type
        feedback_types = learning['feedback_by_type']
        if sum(feedback_types.values()) > 0:
            print("\n📝 FEEDBACK PAR TYPE:")
            for ftype, count in feedback_types.items():
                if count > 0:
                    print(f"  {ftype:12} : {count:,}")

        # Performance
        print("\n⚡ PERFORMANCE:")
        perf = stats['performance']
        print(f"  ⏱️  Temps moyen        : {perf['avg_processing_time']:.3f}s")
        print(f"  ❗ Erreurs total       : {perf['errors_count']:,}")

        if perf['last_error_date']:
            error_date = datetime.fromisoformat(perf['last_error_date'])
            print(f"  📅 Dernière erreur     : {error_date.strftime('%Y-%m-%d %H:%M:%S')}")

        # Statistiques quotidiennes (derniers 7 jours)
        daily = processor.get_daily_statistics(7)
        print("\n📅 ACTIVITÉ (7 derniers jours):")
        for date, day_stats in sorted(daily.items(), reverse=True):
            if any(day_stats[key] > 0 for key in ['emails_processed', 'feedback_processed']):
                print(f"  {date}: {day_stats['emails_processed']} emails, "
                      f"{day_stats['spam_detected']} spams, "
                      f"{day_stats['feedback_processed']} feedbacks")

        # Efficacité des méthodes
        effectiveness = processor.get_detection_effectiveness()
        if 'error' not in effectiveness and any(data['count'] > 0 for data in effectiveness.values()):
            print("\n📈 EFFICACITÉ DES MÉTHODES:")
            for method, data in sorted(effectiveness.items(), key=lambda x: x[1]['count'], reverse=True):
                if data['count'] > 0:
                    print(f"  {method:15} : {data['count']:,} détections ({data['percentage']:5.1f}%)")

        print(f"\n📊 Dernière mise à jour: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        print(f"❌ Erreur lors de l'affichage des stats: {e}")


def show_daily_details(days=3):
    """Affiche les détails quotidiens"""
    try:
        config = ConfigManager('config.yaml')
        processor = EmailProcessor(config)

        print(f"\n📅 DÉTAILS QUOTIDIENS ({days} derniers jours)")
        print("=" * 50)

        daily = processor.get_daily_statistics(days)

        for date, stats in sorted(daily.items(), reverse=True):
            print(f"\n📆 {date}:")
            print(f"  📧 Emails traités     : {stats['emails_processed']:,}")
            print(f"  🗑️  Spams détectés     : {stats['spam_detected']:,}")
            print(f"  ✅ Ham détectés       : {stats['ham_detected']:,}")
            print(f"  📝 Feedback traité    : {stats['feedback_processed']:,}")
            print(f"  ❗ Erreurs            : {stats['errors']:,}")

            if stats['methods_used']:
                print("  🎯 Méthodes utilisées :")
                for method, count in stats['methods_used'].items():
                    print(f"    {method:13} : {count:,}")

    except Exception as e:
        print(f"❌ Erreur lors de l'affichage des détails: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--daily":
        show_daily_details()
    else:
        format_stats()

        print("\n💡 Commandes disponibles:")
        print("  python show_stats.py          # Statistiques générales")
        print("  python show_stats.py --daily  # Détails quotidiens")