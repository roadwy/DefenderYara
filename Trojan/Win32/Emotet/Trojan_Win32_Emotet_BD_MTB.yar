
rule Trojan_Win32_Emotet_BD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 c3 } //1
		$a_02_1 = {88 03 8b 44 24 ?? 83 c4 08 43 48 89 5c 24 ?? 89 44 24 ?? 0f 85 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_BD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 42 8b 4d f8 3b 0d ?? ?? ?? ?? 72 02 eb 35 8b 75 f8 03 75 f0 8b 7d f8 03 7d f0 68 19 10 00 00 8b 15 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 03 45 fc 8b 4d f4 8a 14 31 88 14 38 8b 45 f8 83 c0 01 89 45 f8 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}