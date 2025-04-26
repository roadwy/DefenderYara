
rule Trojan_BAT_Rozena_AZR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 16 13 37 2b 15 00 08 11 37 07 11 37 93 28 15 00 00 0a 9c 00 11 37 17 58 13 37 11 37 08 8e 69 fe 04 13 38 11 38 2d de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rozena_AZR_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.AZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 72 00 6f 00 70 00 70 00 65 00 72 00 4d 00 73 00 66 00 73 00 74 00 61 00 67 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 DropperMsfstaged.exe
		$a_01_1 = {31 37 36 34 65 65 32 33 2d 31 30 34 39 2d 34 31 36 37 2d 62 38 62 65 2d 30 33 38 38 36 36 66 35 37 38 32 38 } //1 1764ee23-1049-4167-b8be-038866f57828
		$a_01_2 = {5a 3a 5c 76 69 73 75 61 6c 73 74 75 64 69 6f 5c 4f 53 45 50 5c 44 72 6f 70 70 65 72 4d 73 66 73 74 61 67 65 64 5c 6f 62 6a 5c 78 36 34 5c 44 65 62 75 67 5c 44 72 6f 70 70 65 72 4d 73 66 73 74 61 67 65 64 2e 70 64 62 } //1 Z:\visualstudio\OSEP\DropperMsfstaged\obj\x64\Debug\DropperMsfstaged.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}