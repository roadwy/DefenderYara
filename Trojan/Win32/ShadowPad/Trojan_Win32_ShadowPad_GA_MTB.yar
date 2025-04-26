
rule Trojan_Win32_ShadowPad_GA_MTB{
	meta:
		description = "Trojan:Win32/ShadowPad.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 25 38 2e 38 78 2d 25 34 2e 34 78 2d 25 34 2e 34 78 2d 25 38 2e 38 78 25 38 2e 38 78 7d } //2 {%8.8x-%4.4x-%4.4x-%8.8x%8.8x}
	condition:
		((#a_01_0  & 1)*2) >=2
 
}