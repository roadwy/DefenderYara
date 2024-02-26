
rule Trojan_Win32_ParallaxRat_CCEE_MTB{
	meta:
		description = "Trojan:Win32/ParallaxRat.CCEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe c3 8a 94 1d 90 01 04 02 c2 8a 8c 05 90 01 04 88 8c 1d 90 00 } //01 00 
		$a_01_1 = {30 0e 46 4f 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}