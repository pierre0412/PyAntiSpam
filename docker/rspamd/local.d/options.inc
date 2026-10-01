# Résolveur DNS : on force l'usage d'unbound (récursif local) plutôt que le
# résolveur système du conteneur. Indispensable pour les DNSBL (voir note
# dans docker/unbound/custom.conf.d/pyantispam.conf).
dns {
  nameserver = ["unbound:53"];
}
