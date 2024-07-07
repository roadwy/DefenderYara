
rule Trojan_BAT_Bulz_SPWR_MTB{
	meta:
		description = "Trojan:BAT/Bulz.SPWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 13 00 00 0a 0a 28 14 00 00 0a 0b 06 07 28 11 00 00 0a 0c 08 0d 2b 00 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}