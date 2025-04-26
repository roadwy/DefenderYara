
rule Trojan_Win32_Neoreblamy_NMC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ff ff ff 83 c8 2f 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ff ff ff 83 e1 2f 2b c1 33 c9 41 6b c9 00 } //2
		$a_01_1 = {eb 08 8b 45 e4 40 40 89 45 e4 83 7d e4 09 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}