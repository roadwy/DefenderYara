
rule Trojan_BAT_Hawkeye_AFD_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 9a 28 90 01 03 0a 9c 11 04 17 58 13 04 11 04 1f 18 32 e7 90 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00 
		$a_01_3 = {47 65 74 46 69 65 6c 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}