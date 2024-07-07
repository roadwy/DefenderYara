
rule Trojan_BAT_Injuke_ABYT_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 11 2b 16 74 90 01 01 00 00 01 2b 16 74 90 01 01 00 00 1b 2b 16 2a 28 90 01 01 00 00 06 2b e8 28 90 01 01 00 00 06 2b e3 28 90 01 01 00 00 06 2b e3 28 90 01 01 00 00 06 2b e3 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}