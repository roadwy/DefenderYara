
rule TrojanDownloader_O97M_InjectorDropper_SA{
	meta:
		description = "TrojanDownloader:O97M/InjectorDropper.SA,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 74 6c 46 69 6c 6c 4d 65 6d 6f 72 79 20 4c 69 62 20 22 6b 33 32 2e 74 6d 70 22 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 4c 69 62 20 22 6b 33 32 2e 74 6d 70 22 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 20 4c 69 62 20 22 6b 33 32 2e 74 6d 70 22 } //02 00 
		$a_01_3 = {65 78 65 63 75 74 65 20 4c 69 62 20 22 6b 33 32 2e 74 6d 70 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 54 68 72 65 61 64 22 } //03 00 
		$a_80_4 = {46 69 6c 65 43 6f 70 79 20 22 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 6b 33 32 2e 74 6d 70 22 } //FileCopy "C:\windows\system32\kernel32.dll", Environ("TEMP") & "\k32.tmp"  00 00 
	condition:
		any of ($a_*)
 
}