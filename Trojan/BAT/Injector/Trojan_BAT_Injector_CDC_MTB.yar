
rule Trojan_BAT_Injector_CDC_MTB{
	meta:
		description = "Trojan:BAT/Injector.CDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 02 09 6f 1b 01 00 0a 03 09 6f 1b 01 00 0a 61 60 0a 00 09 17 58 0d 09 02 6f a6 00 00 0a fe 04 13 04 11 04 2d d9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}