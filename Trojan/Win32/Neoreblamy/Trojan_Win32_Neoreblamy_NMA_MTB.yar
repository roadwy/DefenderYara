
rule Trojan_Win32_Neoreblamy_NMA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 15 6a 04 58 6b c0 00 8b 44 05 f0 48 6a 04 59 6b c9 00 89 44 0d f0 6a 04 58 6b c0 00 } //2
		$a_01_1 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 02 7d 0d 8b 45 ec } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}