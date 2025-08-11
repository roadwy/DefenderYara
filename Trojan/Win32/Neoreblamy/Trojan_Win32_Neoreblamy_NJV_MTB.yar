
rule Trojan_Win32_Neoreblamy_NJV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 } //2
		$a_01_1 = {eb 08 8b 45 f0 40 40 89 45 f0 83 7d f0 07 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Neoreblamy_NJV_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 58 6b c0 00 8b 84 05 b4 fe ff ff 40 6a 04 59 6b c9 00 } //1
		$a_01_1 = {eb 07 8b 45 b8 40 89 45 b8 83 7d b8 03 7d 10 8b 45 b8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}