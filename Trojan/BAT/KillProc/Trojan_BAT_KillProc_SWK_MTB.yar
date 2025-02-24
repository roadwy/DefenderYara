
rule Trojan_BAT_KillProc_SWK_MTB{
	meta:
		description = "Trojan:BAT/KillProc.SWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 9a 0b 28 ?? 00 00 0a 00 07 28 ?? 00 00 0a 13 08 16 13 07 2b 14 11 08 11 07 9a 0c 08 6f ?? 00 00 0a 00 11 07 17 d6 13 07 00 11 07 11 08 8e b7 fe 04 13 09 11 09 2d de 11 05 17 d6 13 05 00 11 05 11 06 8e b7 fe 04 13 09 11 09 2d b0 } //2
		$a_03_1 = {00 73 3c 00 00 0a 0a 06 6f 3d 00 00 0a 00 2b 07 28 ?? 00 00 0a 00 00 06 6f ?? 00 00 0a 02 20 e8 03 00 00 d8 6a fe 04 0b 07 2d e5 06 6f ?? 00 00 0a 00 00 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}