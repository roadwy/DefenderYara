
rule Backdoor_BAT_AveMariaRAT_C_MTB{
	meta:
		description = "Backdoor:BAT/AveMariaRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 04 1c d6 5d 8c } //02 00 
		$a_03_1 = {da 9a 0b 73 90 01 02 00 0a 0c 90 09 0e 00 06 74 90 01 01 00 00 01 6f 90 01 02 00 0a 03 1f 0a 90 00 } //02 00 
		$a_03_2 = {00 00 01 a2 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 02 00 0a 90 09 0b 00 18 8d 90 01 01 00 00 01 25 17 16 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}