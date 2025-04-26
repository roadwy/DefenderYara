
rule Trojan_Win32_PovStealer_AD_MTB{
	meta:
		description = "Trojan:Win32/PovStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d c7 0f b6 55 c7 c1 fa 06 0f b6 45 c7 c1 e0 02 0b d0 88 55 c7 8b 4d c8 8a 55 c7 88 54 0d d8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}