
rule Trojan_Win32_RisePro_CCDY_MTB{
	meta:
		description = "Trojan:Win32/RisePro.CCDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0d 90 01 01 fe ff ff 50 e8 90 01 04 88 84 0d 90 01 04 41 83 f9 90 00 } //1
		$a_01_1 = {8a 45 08 34 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}