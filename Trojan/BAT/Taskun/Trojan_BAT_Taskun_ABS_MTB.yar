
rule Trojan_BAT_Taskun_ABS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 07 09 58 08 11 04 58 6f 90 01 01 00 00 0a 13 0a 12 0a 28 90 01 01 00 00 0a 13 08 11 06 11 05 11 08 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf 09 17 58 0d 09 90 00 } //01 00 
		$a_01_1 = {42 69 74 6d 61 70 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}