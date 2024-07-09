
rule Trojan_Win32_Trickbot_SD_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 8b 55 0c 8d 1c 02 8b 45 e4 8b 55 0c 01 d0 0f b6 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 c7 8b 45 e4 ba 00 00 00 00 f7 f7 89 d1 89 ca 8b 45 08 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 8b 45 e4 3b 45 10 75 } //1
		$a_03_1 = {89 14 24 ff d0 8b 45 c4 c7 04 24 ?? ?? ?? ?? ff d0 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}