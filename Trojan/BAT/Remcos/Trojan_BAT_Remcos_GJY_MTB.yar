
rule Trojan_BAT_Remcos_GJY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 13 05 16 13 06 11 05 12 06 28 ?? ?? ?? 0a 00 08 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 de 0d 11 06 2c 08 11 05 28 ?? ?? ?? 0a 00 dc 00 11 04 18 58 13 04 11 04 07 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}