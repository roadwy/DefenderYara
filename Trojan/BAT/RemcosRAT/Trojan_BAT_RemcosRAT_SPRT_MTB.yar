
rule Trojan_BAT_RemcosRAT_SPRT_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SPRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 } //3
		$a_03_1 = {03 11 06 11 07 11 08 94 91 6f ?? 00 00 0a 00 00 11 08 17 58 13 08 11 08 09 19 28 ?? 00 00 0a fe 04 13 09 11 09 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}