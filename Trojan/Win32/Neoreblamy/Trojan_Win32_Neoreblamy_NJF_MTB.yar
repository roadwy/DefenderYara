
rule Trojan_Win32_Neoreblamy_NJF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 e8 83 c2 01 89 55 e8 8b 45 e8 3b 45 e0 } //1
		$a_03_1 = {eb 0d 8b 45 f0 89 8c 85 ?? ?? ff ff ff 45 f0 39 7d f0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}