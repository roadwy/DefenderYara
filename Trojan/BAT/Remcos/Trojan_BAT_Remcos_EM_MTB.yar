
rule Trojan_BAT_Remcos_EM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 08 fe 01 13 07 11 07 2c 02 17 0d 03 09 17 28 90 01 03 0a 28 90 01 03 0a 0b 11 04 02 11 05 17 28 90 01 03 0a 28 90 01 03 0a 07 08 d8 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 13 04 09 17 d6 0d 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 ac 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_3 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_81_4 = {54 6f 53 74 72 69 6e 67 } //00 00  ToString
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_EM_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 73 00 78 00 77 00 69 00 71 00 2e 00 58 00 67 00 74 00 61 00 78 00 62 00 78 00 6d 00 72 00 79 00 76 00 62 00 7a 00 77 00 62 00 68 00 68 00 } //01 00  Csxwiq.Xgtaxbxmryvbzwbhh
		$a_01_1 = {41 00 66 00 74 00 6b 00 70 00 79 00 79 00 6c 00 6a 00 7a 00 79 00 75 00 77 00 74 00 6b 00 78 00 79 00 66 00 73 00 64 00 } //01 00  Aftkpyyljzyuwtkxyfsd
		$a_01_2 = {48 00 78 00 76 00 6b 00 68 00 64 00 73 00 75 00 } //01 00  Hxvkhdsu
		$a_01_3 = {6e 69 61 4d 6c 6c 44 72 6f 43 5f } //01 00  niaMllDroC_
		$a_01_4 = {6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //01 00  margorp sihT!
		$a_01_5 = {62 6c 75 65 33 32 5f 63 2e 65 78 65 } //00 00  blue32_c.exe
	condition:
		any of ($a_*)
 
}