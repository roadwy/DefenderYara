
rule Trojan_Win32_Neoreblamy_NJY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 04 7d 0d 8b 45 e4 } //2
		$a_01_1 = {74 12 8b f3 8b cb c1 fe 03 83 e1 07 b2 01 d2 e2 08 54 3e 0c 43 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}