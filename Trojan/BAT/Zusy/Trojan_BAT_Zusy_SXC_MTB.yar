
rule Trojan_BAT_Zusy_SXC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 04 00 00 8d 0f 00 00 01 0d 08 09 6f ?? 00 00 0a 00 07 8e 69 09 8e 69 58 8d 0f 00 00 01 13 04 07 16 11 04 16 07 8e 69 28 ?? 00 00 0a 00 09 16 11 04 07 8e 69 09 8e 69 28 ?? 00 00 0a 00 72 ?? ?? 00 70 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 ?? ?? 00 70 08 20 e8 03 00 00 20 0f 27 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}