
rule Trojan_Win32_Neoreblamy_NFA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 03 } //2
		$a_03_1 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ff ff ff 83 c8 53 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ff ff ff 83 e1 53 2b c1 33 c9 41 6b c9 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}