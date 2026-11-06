# Sécurité

Projet personnel : audit local de ses propres données. L'application écoute
uniquement sur 127.0.0.1 et n'envoie aucune télémétrie.

## Signaler une faille
Utiliser « Report a vulnerability » (onglet Security du dépôt GitHub) plutôt
qu'une issue publique. Réponse au mieux, sans délai garanti.

## Ce qui ne doit jamais être versionné
Fuites connues, demandes, journal, rapports, configuration : voir `.gitignore`.
Si l'un de ces fichiers est poussé par erreur, le considérer comme public :
changer les éléments concernés et purger l'historique.

## Vérifier un téléchargement
Chaque release contient `audit-donnees-perso-x86_64.AppImage.sha256` :
`sha256sum -c audit-donnees-perso-x86_64.AppImage.sha256`
