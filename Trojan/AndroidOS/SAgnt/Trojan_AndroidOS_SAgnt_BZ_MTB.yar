
rule Trojan_AndroidOS_SAgnt_BZ_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BZ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {6e 10 1a 01 0a 00 0a 03 dc 08 03 02 12 19 33 98 33 00 d8 03 03 01 db 08 03 02 23 87 ba 00 22 08 62 00 70 10 28 01 08 00 1a 09 09 00 6e 20 2d 01 98 00 0c 08 6e 20 2d 01 a8 00 0c 08 6e 10 2e 01 08 00 0c 0a 12 05 12 04 35 34 1b 00 d8 08 04 02 6e 30 20 01 4a 08 0c 08 13 09 10 00 71 20 f7 00 98 00 0a 08 8d 88 4f 08 07 05 d8 05 05 01 d8 04 04 02 28 eb db 08 03 02 } //02 00 
		$a_00_1 = {db 08 03 02 23 87 ba 00 28 e4 12 01 22 06 8b 00 6e 10 17 01 0b 00 0c 08 1a 09 97 00 70 30 93 01 86 09 1a 08 97 00 71 10 91 01 08 00 0c 00 12 28 6e 30 92 01 80 06 6e 20 90 01 70 00 0c 01 22 08 60 00 70 20 0f 01 18 00 11 08 0d 02 6e 10 f2 00 02 00 28 f6 } //01 00 
		$a_00_2 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //01 00  getInstalledApplications
		$a_00_3 = {67 65 74 65 78 74 65 72 6e 61 6c 73 74 6f 72 61 67 65 64 69 72 65 63 74 6f 72 79 } //01 00  getexternalstoragedirectory
		$a_00_4 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00  DexClassLoader
	condition:
		any of ($a_*)
 
}