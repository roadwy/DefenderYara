
rule Trojan_AndroidOS_Climap_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Climap.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 68 6f 74 6f 54 61 6b 65 72 } //01 00  PhotoTaker
		$a_01_1 = {53 4d 53 4c 69 73 74 65 72 } //01 00  SMSLister
		$a_01_2 = {44 69 72 4c 69 73 74 65 72 } //01 00  DirLister
		$a_01_3 = {76 69 73 69 74 41 6c 6c 44 69 72 73 41 6e 64 46 69 6c 65 73 } //00 00  visitAllDirsAndFiles
	condition:
		any of ($a_*)
 
}