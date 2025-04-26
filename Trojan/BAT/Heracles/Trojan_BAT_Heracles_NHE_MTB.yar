
rule Trojan_BAT_Heracles_NHE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 19 5a 58 47 09 16 94 04 59 fe 04 16 fe 01 11 06 11 07 19 5a 58 47 09 16 94 04 58 } //5
		$a_01_1 = {5a 61 68 75 72 61 43 48 2e 55 74 69 6c 73 2e 57 69 6e 53 74 72 75 63 74 73 } //1 ZahuraCH.Utils.WinStructs
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Heracles_NHE_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 00 00 00 00 00 11 04 11 0c 28 ?? 00 00 06 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 fe ?? ?? 00 } //5
		$a_01_1 = {4f 69 78 6c 79 78 6c 62 } //1 Oixlyxlb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Heracles_NHE_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b fa 02 06 74 ?? 00 00 1b 18 9a 06 74 ?? 00 00 1b 1a 9a 28 ?? 00 00 06 } //5
		$a_01_1 = {51 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Qe.Resources.resources
		$a_01_2 = {53 70 65 63 69 61 6c 44 69 72 65 63 74 6f 72 69 65 73 50 72 6f 78 79 } //1 SpecialDirectoriesProxy
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}