
rule Backdoor_BAT_Remcos_SMK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 08 59 0d 09 16 30 03 16 2b 01 17 13 04 08 19 58 04 fe 02 16 fe 01 13 05 11 05 2c 07 11 04 17 fe 01 2b 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Backdoor_BAT_Remcos_SMK_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.SMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 12 02 28 7f 00 00 0a 6f 80 00 00 0a 03 12 02 28 81 00 00 0a 6f 80 00 00 0a 03 12 02 28 82 00 00 0a 6f 80 00 00 0a 2b 0b 03 6f 83 00 00 0a 19 58 04 31 cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}