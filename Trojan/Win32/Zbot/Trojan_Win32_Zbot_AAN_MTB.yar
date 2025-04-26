
rule Trojan_Win32_Zbot_AAN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 55 f4 8b 02 03 45 f4 8b 4d 08 03 4d f4 89 01 c7 45 fc ?? ?? ?? ?? 8b 55 f4 83 c2 18 89 15 ?? ?? ?? ?? 8b 45 f8 89 45 f0 c7 45 fc 6a 01 00 00 8b 0d c0 21 44 00 89 4d ec 8b 55 08 03 55 f4 8b 02 33 45 ec 8b 4d 08 03 4d f4 89 01 eb 97 } //10
		$a_01_1 = {8b 45 08 89 45 fc 8b 4d 0c 89 4d f8 8b 55 fc 3b 55 f8 73 07 8b 45 fc eb 05 eb 03 8b 45 f8 8b e5 5d c3 } //10
		$a_01_2 = {57 65 74 50 4a 6f 63 41 34 64 72 65 4b 73 } //1 WetPJocA4dreKs
		$a_01_3 = {4c 6f 61 64 64 69 62 72 39 72 79 45 } //1 Loaddibr9ryE
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}