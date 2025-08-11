
rule Trojan_Win32_Neoreblamy_NFI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00 } //2
		$a_03_1 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec ?? 7d 10 8b 45 ec } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}