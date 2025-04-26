
rule Backdoor_BAT_Remcos_VRAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.VRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 06 13 05 20 ?? 00 00 00 fe 0e 04 00 38 ?? ff ff ff 28 ?? 00 00 0a 11 00 28 ?? 00 00 06 13 01 } //3
		$a_03_1 = {11 02 11 05 6f ?? 00 00 0a 20 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}