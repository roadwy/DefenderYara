
rule Trojan_Win32_ParallaxRat_CCEE_MTB{
	meta:
		description = "Trojan:Win32/ParallaxRat.CCEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d } //1
		$a_01_1 = {30 0e 46 4f 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}