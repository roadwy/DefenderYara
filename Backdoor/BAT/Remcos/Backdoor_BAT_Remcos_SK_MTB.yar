
rule Backdoor_BAT_Remcos_SK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 73 01 00 00 0a 72 01 00 00 70 28 ?? ?? ?? 0a 0a 06 16 06 8e 69 28 ?? ?? ?? 0a 06 0b dd 03 00 00 00 26 de db } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Backdoor_BAT_Remcos_SK_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 59 13 06 2b 17 00 28 ?? ?? ?? 06 07 11 06 9a 6f ?? ?? ?? 06 00 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d db } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}