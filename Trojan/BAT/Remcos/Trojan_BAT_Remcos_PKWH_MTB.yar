
rule Trojan_BAT_Remcos_PKWH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PKWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 12 04 28 ?? 00 00 0a 1f 10 62 12 04 28 ?? 00 00 0a 1e 62 60 12 04 28 ?? 00 00 0a 60 13 09 08 25 7b ?? 00 00 04 11 09 } //6
		$a_03_1 = {25 16 11 09 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 11 09 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 11 09 20 ?? 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 08 25 7b ?? 00 00 04 08 7b ?? 00 00 04 6a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}