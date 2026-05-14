
rule Trojan_Win32_Neoreblamy_NUY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 ec 83 c2 01 89 55 ec 83 7d ec 01 7d 0d 8b 45 ec } //1
		$a_03_1 = {6b c2 00 83 bc 05 ?? ?? ff ff 00 74 02 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}