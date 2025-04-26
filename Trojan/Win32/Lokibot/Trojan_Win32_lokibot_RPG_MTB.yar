
rule Trojan_Win32_lokibot_RPG_MTB{
	meta:
		description = "Trojan:Win32/lokibot.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 db 8b 45 08 03 45 e8 6a 02 89 45 e4 8a 00 88 45 fb 58 d1 e8 75 fc } //1
		$a_01_1 = {75 03 8a 45 08 39 3d 30 4d 57 00 8b 7d f4 88 01 74 1f } //1
		$a_01_2 = {8a 14 06 88 10 40 49 75 f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}