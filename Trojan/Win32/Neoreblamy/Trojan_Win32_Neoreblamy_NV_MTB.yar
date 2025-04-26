
rule Trojan_Win32_Neoreblamy_NV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 51 08 b8 ff ff ff 3f 2b 11 c1 fa 02 8b ca d1 e9 2b c1 3b c2 73 04 } //2
		$a_03_1 = {55 8b ec 51 51 83 65 fc 00 56 51 8b f1 e8 ?? ?? ff ff 59 8b c6 5e 8b e5 5d c3 55 } //1
		$a_03_2 = {eb 0d 8b 0a 8b 06 c7 04 88 ?? ?? ff ff ff 02 83 3a 01 7c ee } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}