
rule Trojan_Win32_Neoreblamy_NLE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 01 7d 0d 8b 45 ec } //2
		$a_01_1 = {eb 07 8b 45 f4 48 89 45 f4 83 7d f4 f6 } //1
		$a_03_2 = {50 33 d2 42 33 c9 e8 ?? ?? ff ff 59 59 8b f0 8d bd ?? ff ff ff a5 a5 a5 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}