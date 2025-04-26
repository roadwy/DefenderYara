
rule Trojan_BAT_Zusy_SPUF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SPUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 08 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 02 73 18 00 00 0a 13 04 00 11 04 09 16 73 19 00 00 0a 13 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}