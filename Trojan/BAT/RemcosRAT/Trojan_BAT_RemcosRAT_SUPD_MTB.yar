
rule Trojan_BAT_RemcosRAT_SUPD_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SUPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 19 8d 84 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}