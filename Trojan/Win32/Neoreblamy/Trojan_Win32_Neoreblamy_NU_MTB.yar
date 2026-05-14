
rule Trojan_Win32_Neoreblamy_NU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 22 83 65 ec 00 eb 07 8b 45 ec 40 89 45 ec 81 7d ec } //1
		$a_01_1 = {eb 04 83 65 dc 00 8a 45 dc 88 45 eb 8b 45 ec 83 e0 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}