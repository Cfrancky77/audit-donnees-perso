"""Point d'entrée de l'exécutable Windows (PyInstaller, un seul .exe).

Dans l'exécutable, sys.executable est l'application elle-même (comme le fichier .AppImage sous Linux) :
l'application lance Maigret, Holehe et Sherlock en se relançant avec « --py -m module » ou
« --py -c code ». Ce fichier exécute ces deux formes puis, sinon, démarre l'application.

  audit-donnees-perso.exe              fenêtre d'application (comme --window)
  audit-donnees-perso.exe --serve      serveur seul, sans fenêtre
  audit-donnees-perso.exe --py -m ...  exécute un module Python (usage interne)
  audit-donnees-perso.exe --py -c ...  exécute du code Python (usage interne)
  autres options                       voir --help (--rescan, --install-launcher, --install-timer, --data-dir)
"""
import os
import runpy
import sys


def run_python(args):
    """Équivalent de « python [-I] [-u] -m module ... » et « python -c code ... »."""
    args = [a for a in args if a not in ("-I", "-u", "-E", "-s")]
    if len(args) >= 2 and args[0] == "-m":
        module, rest = args[1], args[2:]
        sys.argv = [module] + rest
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return 0
    if len(args) >= 2 and args[0] == "-c":
        code, rest = args[1], args[2:]
        sys.argv = ["-c"] + rest
        exec(compile(code, "<string>", "exec"), {"__name__": "__main__"})  # noqa: S102
        return 0
    sys.stderr.write("usage : --py -m module [args] | --py -c code [args]\n")
    return 2


def hide_own_console():
    """Double-clic : masque la console noire. Lancé depuis un terminal, on ne touche à rien."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32, user32 = ctypes.windll.kernel32, ctypes.windll.user32
        procs = (ctypes.c_uint * 4)()
        if kernel32.GetConsoleProcessList(procs, 4) == 1:  # nous seuls dans cette console
            hwnd = kernel32.GetConsoleWindow()
            if hwnd:
                user32.ShowWindow(hwnd, 0)
    except Exception:  # noqa: BLE001
        pass


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--py":
        return run_python(argv[1:])
    if "--serve" in argv:
        argv = [a for a in argv if a != "--serve"]  # sans mode : serveur seul
    elif not any(a in argv for a in ("--window", "--rescan", "--install-launcher", "--install-timer", "-h", "--help")):
        argv = argv + ["--window"]  # double-clic : fenêtre
        hide_own_console()
    sys.argv = [sys.argv[0]] + argv
    import audit_donnees_perso
    audit_donnees_perso.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
