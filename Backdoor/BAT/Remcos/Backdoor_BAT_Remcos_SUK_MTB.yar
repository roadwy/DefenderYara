
rule Backdoor_BAT_Remcos_SUK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1f 0a fe 02 13 06 11 06 2c 0c 07 08 66 5f 07 66 08 5f 60 0d 2b 13 00 11 05 17 1f 14 6f 29 01 00 0a 13 04 00 17 13 07 2b d5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}