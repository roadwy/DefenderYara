
rule Backdoor_BAT_Remcos_SY_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 15 1d 5a 11 10 58 1f 13 5d 13 16 11 16 18 5d 16 fe 01 13 17 11 17 2c 08 00 11 16 18 5a 13 16 00 00 11 15 17 58 13 15 11 15 19 fe 04 13 18 11 18 2d cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}