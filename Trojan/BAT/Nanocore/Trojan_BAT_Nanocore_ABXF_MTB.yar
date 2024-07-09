
rule Trojan_BAT_Nanocore_ABXF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 34 16 13 05 2b 1f 07 11 04 11 05 6f ?? 00 00 0a 13 06 08 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 07 6f ?? 00 00 0a 32 d7 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}