
rule Trojan_Win32_LummaC_ZUU_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ZUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e1 02 09 ca 0f af d6 01 fa 8b 7c 24 2c 83 f0 5b 01 c2 80 c2 01 8b 84 24 a8 00 00 00 88 54 04 6b 8b 84 24 ?? ?? ?? ?? d1 e0 83 e0 02 83 b4 24 a8 00 00 00 01 01 84 24 a8 00 00 00 8b 84 24 a8 00 00 00 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}