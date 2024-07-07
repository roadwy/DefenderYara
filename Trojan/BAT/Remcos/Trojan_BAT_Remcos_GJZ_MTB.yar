
rule Trojan_BAT_Remcos_GJZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 13 05 16 13 06 11 05 12 06 28 90 01 03 0a 00 09 08 11 04 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 dd 10 00 00 00 11 06 39 90 01 03 00 11 05 28 90 01 03 0a 00 dc 00 11 04 18 58 13 04 11 04 08 6f 90 01 03 0a fe 04 13 07 11 07 2d ac 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}