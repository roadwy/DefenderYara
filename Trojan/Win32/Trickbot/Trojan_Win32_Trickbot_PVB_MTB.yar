
rule Trojan_Win32_Trickbot_PVB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 3c c7 45 ec 90 01 04 c7 45 fc 00 00 00 00 eb 90 01 01 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ff 2b 00 00 0f 8d 90 01 04 68 90 01 04 e8 90 01 04 83 c4 04 68 90 01 04 e8 90 01 04 83 c4 04 68 90 01 04 e8 90 00 } //2
		$a_02_1 = {55 8b ec 83 ec 18 c7 45 fc 00 00 00 00 c7 45 ec 00 00 00 00 c7 45 f0 90 01 04 c7 45 fc 00 00 00 00 eb 90 01 01 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ff 2b 00 00 0f 8d 90 01 04 68 90 01 04 e8 90 01 04 83 c4 04 68 90 01 04 e8 90 01 04 83 c4 04 68 90 01 04 e8 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}