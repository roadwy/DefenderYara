
rule Trojan_Win32_RisePro_YAB_MTB{
	meta:
		description = "Trojan:Win32/RisePro.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b f3 ff 45 ?? 66 0f a4 c3 ?? 0f b7 3c 0f 0f c9 80 e1 0a 0f b7 df d3 c9 66 d3 f9 8b c8 f9 c1 e9 0b f6 c7 3e 66 85 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}