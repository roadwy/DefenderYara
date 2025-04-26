
rule Trojan_BAT_Remcos_PLICH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PLICH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 62 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0d 02 19 8d ?? 00 00 01 25 16 09 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 09 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 09 20 ?? 00 00 00 5f d2 9c 6f ?? 00 00 0a 06 09 5a 16 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}