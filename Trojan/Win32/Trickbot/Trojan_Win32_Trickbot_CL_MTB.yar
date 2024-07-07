
rule Trojan_Win32_Trickbot_CL_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f b6 02 03 45 f0 8b 4d f4 03 4d fc 0f be 11 03 c2 33 d2 f7 35 90 01 04 89 55 f0 8b 45 08 03 45 fc 8a 08 88 4d fb 8b 55 08 03 55 fc 8b 45 08 03 45 f0 8a 08 88 0a 8b 55 08 03 55 f0 8a 45 fb 88 02 eb 90 00 } //1
		$a_00_1 = {8b 45 08 03 45 fc 8a 4d fc 88 08 8b 45 fc 33 d2 f7 75 10 8b 45 f4 03 45 fc 8b 4d 0c 8a 14 11 88 10 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}