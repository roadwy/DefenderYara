
rule Backdoor_BAT_NanoCoreRAT_D_MTB{
	meta:
		description = "Backdoor:BAT/NanoCoreRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {1f 2d 9d 6f 90 09 1c 00 28 90 01 01 00 00 06 72 90 01 01 03 00 70 72 90 01 01 03 00 70 6f 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 25 16 90 00 } //02 00 
		$a_03_1 = {11 06 9a 1f 10 28 90 01 01 00 00 0a 9c 90 00 } //02 00 
		$a_03_2 = {1f 25 9d 6f 90 01 01 00 00 0a 13 04 90 09 09 00 04 17 8d 90 01 01 00 00 01 25 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}