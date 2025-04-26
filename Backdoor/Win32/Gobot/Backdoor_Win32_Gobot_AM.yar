
rule Backdoor_Win32_Gobot_AM{
	meta:
		description = "Backdoor:Win32/Gobot.AM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {47 68 6f 73 74 42 4f 54 } //1 GhostBOT
		$a_02_1 = {8d 55 ec b8 01 00 00 00 e8 ?? ?? ff ff 8b 45 ec 50 a1 ?? ?? ?? ?? 8b 00 ff d0 85 c0 74 3f 68 88 13 00 00 a1 ?? ?? ?? ?? 8b 00 ff d0 8d 95 e8 fe ff ff b8 01 00 00 00 e8 ?? ?? ff ff 8b 95 e8 fe ff ff 8d 85 ec fe ff ff b9 ff 00 00 00 e8 ?? ?? ff ff 8d 85 ec fe ff ff e8 ?? ?? ff ff 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ff ff 50 a1 ?? ?? ?? ?? 8b 00 ff d0 3d 02 01 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}