
rule Trojan_BAT_Injuke_NIJ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 1f 00 00 70 2b 03 2b 08 2a 28 90 01 01 00 00 06 2b f6 28 90 01 01 00 00 06 2b f1 90 00 } //01 00 
		$a_01_1 = {49 00 79 00 6c 00 68 00 71 00 62 00 68 00 6c 00 76 00 61 00 66 00 73 00 76 00 66 00 } //01 00 
		$a_01_2 = {43 6f 6d 70 75 74 65 72 20 53 65 6e 74 69 6e 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}