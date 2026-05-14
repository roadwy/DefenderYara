
rule Trojan_Win32_Neoreblamy_NUA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 01 7d 0d 8b 45 ec } //2
		$a_03_1 = {58 6b c0 00 8d 84 05 ?? ?? ff ff 6a 0c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}