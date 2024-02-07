
rule Trojan_O97M_JhRAT_MSR{
	meta:
		description = "Trojan:O97M/JhRAT!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 64 72 69 76 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 75 63 3f 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 69 64 3d 31 64 2d 74 6f 45 38 39 51 6e 4e 35 5a 68 75 4e 5a 49 63 32 69 46 34 2d 63 62 4b 57 74 6b 30 46 44 } //01 00  https://drive.google.com/uc?export=download&id=1d-toE89QnN5ZhuNZIc2iF4-cbKWtk0FD
		$a_00_1 = {28 22 54 65 6d 70 22 29 20 2b 20 22 5c 22 20 2b 20 70 72 63 6e 61 6d 65 20 2b 20 22 2e 65 78 65 22 } //01 00  ("Temp") + "\" + prcname + ".exe"
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 64 64 66 64 73 66 64 73 66 64 77 77 28 29 } //00 00  Function ddfdsfdsfdww()
	condition:
		any of ($a_*)
 
}