
rule Trojan_BAT_Lazy_SPPX_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 6f 8f 00 00 0a 16 73 90 00 00 0a 13 0d 11 0d 11 07 28 64 00 00 06 de 14 11 0d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}