
rule Trojan_Win32_Neoreblamy_NFK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 8c 40 89 45 8c 83 7d 8c 01 7d 0d 8b 45 8c } //2
		$a_01_1 = {eb 07 8b 45 cc 48 89 45 cc 83 7d cc e9 } //1
		$a_03_2 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}