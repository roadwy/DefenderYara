
rule TrojanProxy_Win32_Kabwall_A{
	meta:
		description = "TrojanProxy:Win32/Kabwall.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {bb 05 00 00 00 e8 ?? ?? ?? ff b8 09 00 00 00 e8 ?? ?? ?? ff 8b f0 8d 55 f8 8b c6 e8 ?? ?? ?? ff 8b 55 f8 8d 45 fc e8 ?? ?? ?? ff 4b 75 d7 } //1
		$a_03_1 = {8d 7b 0a a5 a5 a5 a5 5f 5e 89 73 04 66 c7 43 08 3c 00 53 e8 ?? ?? ?? ff 84 c0 74 08 3c 06 0f 85 ?? 00 00 00 } //1
		$a_03_2 = {84 c0 75 29 ff 45 c4 83 7d c4 1e 7e 0d 8b 45 fc e8 ?? ?? ?? ff e9 ?? ?? 00 00 68 88 13 00 00 e8 ?? ?? ?? ff 8b 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}