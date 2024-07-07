
rule Trojan_Win32_Trickbot_BA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8b cb 99 f7 f9 8b 4d 90 01 01 8b 75 90 01 01 0f be 0c 31 51 0f b6 04 3a 50 e8 90 01 04 83 c4 10 88 06 46 ff 4d 90 01 01 89 75 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 74 49 40 25 39 49 65 40 55 76 7c 54 65 4e 25 72 6e 7d 23 } //1 vtI@%9Ie@Uv|TeN%rn}#
		$a_02_1 = {6a 00 6a 00 ff 15 90 01 04 8b 44 24 10 8d 0c 06 33 d2 6a 14 8b c6 5b f7 f3 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 14 75 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_BA_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 33 c0 8a 04 11 8d 3c 11 89 85 90 01 04 db 85 90 01 04 dc 65 90 01 01 dc 15 90 01 04 df e0 f6 c4 01 74 90 01 01 dc 05 90 01 04 83 ec 08 dd 1c 24 ff 15 90 01 04 ff 15 90 01 04 8b 8d 90 01 04 88 07 01 4d 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}