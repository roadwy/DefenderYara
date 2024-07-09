
rule Trojan_Win32_Iflar{
	meta:
		description = "Trojan:Win32/Iflar,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {e8 54 09 00 00 59 6a 01 be ?? ?? ?? 00 5b 8d 4d f0 56 89 5d fc e8 ?? ?? 01 00 56 8d 4d ec c6 45 fc 02 e8 ?? ?? 01 00 85 c0 7c 12 8b 4d 08 68 ?? ?? ?? 00 e8 ?? ?? 01 00 89 5d e8 eb 14 8d 45 f0 68 ?? ?? ?? 00 50 } //1
		$a_02_1 = {50 8d 45 f0 68 ?? ?? ?? 00 50 e8 ?? ?? 01 00 83 c4 14 ff 75 f0 53 6a 01 53 ff 15 ?? ?? ?? 00 83 f8 ff 89 86 ?? 01 00 00 75 08 88 9e ?? 01 00 00 eb 07 c6 86 ?? 01 00 00 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Iflar_2{
	meta:
		description = "Trojan:Win32/Iflar,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {e8 54 09 00 00 59 6a 01 be ?? ?? ?? 00 5b 8d 4d f0 56 89 5d fc e8 ?? ?? 01 00 56 8d 4d ec c6 45 fc 02 e8 ?? ?? 01 00 85 c0 7c 12 8b 4d 08 68 ?? ?? ?? 00 e8 ?? ?? 01 00 89 5d e8 eb 14 8d 45 f0 68 ?? ?? ?? 00 50 } //1
		$a_02_1 = {50 8d 45 f0 68 ?? ?? ?? 00 50 e8 ?? ?? 01 00 83 c4 14 ff 75 f0 53 6a 01 53 ff 15 ?? ?? ?? 00 83 f8 ff 89 86 ?? (01|02) 00 00 75 08 88 9e ?? 01 00 00 eb 07 c6 86 ?? 01 00 00 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}