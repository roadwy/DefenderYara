
rule Trojan_Win32_Trickbot_RB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 ec 14 02 00 00 c7 45 f8 00 00 00 00 c7 85 28 fe ff ff 00 00 00 00 c7 85 2c fe ff ff 00 00 00 00 c7 85 ec fd ff ff 4c 00 00 00 b8 6b 00 00 00 66 89 85 f0 fd ff ff b9 65 00 00 00 66 89 8d f2 fd ff ff ba 72 00 00 00 66 89 95 f4 fd ff ff b8 6e 00 00 00 66 89 85 f6 fd ff ff b9 65 00 00 00 66 89 8d f8 fd ff ff ba 6c 00 00 00 66 89 95 fa fd ff ff b8 33 00 00 00 66 89 85 fc fd ff ff b9 32 00 00 00 66 89 8d fe fd ff ff ba 2e 00 00 00 66 89 95 00 fe ff ff b8 64 00 00 00 66 89 85 02 fe ff ff b9 6c 00 00 00 66 89 8d 04 fe ff ff ba 6c 00 00 00 66 89 95 06 fe ff ff 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}