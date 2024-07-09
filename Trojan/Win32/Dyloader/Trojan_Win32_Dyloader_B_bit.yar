
rule Trojan_Win32_Dyloader_B_bit{
	meta:
		description = "Trojan:Win32/Dyloader.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 0c 73 32 8b 4d 08 8a 11 32 55 f8 8b 45 08 88 10 8b 4d 08 8a 11 02 55 f8 8b 45 08 88 10 8b 4d 08 8a 11 32 55 f8 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb bd } //1
		$a_03_1 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 4d 08 51 6a 00 ff 15 ?? ?? ?? 10 3b f4 e8 ?? ?? ?? 00 89 45 } //1
		$a_03_2 = {83 7d fc 00 0f 84 9b 00 00 00 8b 8d ?? ?? ?? ff 51 8b 55 f8 52 e8 ?? ?? ?? ff 83 c4 08 85 c0 74 28 8b f4 6a 40 68 00 30 00 00 8b 45 18 50 8b 4d 0c 8b 51 34 52 8b 45 f8 50 ff 55 fc 3b f4 e8 ?? ?? ?? 00 89 85 ?? ?? ?? ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}