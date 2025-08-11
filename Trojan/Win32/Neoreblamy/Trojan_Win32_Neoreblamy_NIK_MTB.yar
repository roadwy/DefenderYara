
rule Trojan_Win32_Neoreblamy_NIK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 03 } //1
		$a_01_1 = {8b 45 f8 40 40 89 45 f8 83 7d f8 22 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}