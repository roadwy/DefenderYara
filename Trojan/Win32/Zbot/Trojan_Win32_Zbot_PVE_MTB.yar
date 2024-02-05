
rule Trojan_Win32_Zbot_PVE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 a5 28 ff ff ff 8b 85 28 ff ff ff 81 85 6c fd ff ff 90 01 04 81 6d ac 90 01 04 81 85 c4 fd ff ff 90 01 04 30 0c 37 90 00 } //02 00 
		$a_00_1 = {0f be 11 0f b6 85 63 ff ff ff 33 d0 8b 4d 08 03 4d 0c 88 11 8b 55 0c 83 ea 01 89 55 0c e9 } //00 00 
	condition:
		any of ($a_*)
 
}