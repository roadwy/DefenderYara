
rule Backdoor_BAT_Remcos_SGK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 12 06 28 46 00 00 0a 6f 44 00 00 0a 00 07 6f 45 00 00 0a 20 00 1e 01 00 fe 04 13 08 11 08 39 0e 00 00 00 07 12 06 28 47 00 00 0a 6f 44 00 00 0a 00 00 11 05 17 58 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}