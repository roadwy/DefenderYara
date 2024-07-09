
rule Trojan_Win32_CryptBot_GTS_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 45 08 8b 4d 10 03 0d ?? ?? ?? ?? 33 4d 20 83 e9 24 03 c9 2b 4d 08 89 0d ?? ?? ?? ?? 68 45 a0 74 00 ff 15 ?? ?? ?? ?? 89 45 fc 83 f8 00 0f 85 c0 c5 ff ff } //10
		$a_02_1 = {8b ce 81 f1 ?? ?? ?? ?? 83 e9 1d 03 0d ?? ?? ?? ?? 33 ce 03 0d 91 a2 74 00 89 4d e4 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}