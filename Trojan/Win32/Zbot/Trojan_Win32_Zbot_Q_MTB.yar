
rule Trojan_Win32_Zbot_Q_MTB{
	meta:
		description = "Trojan:Win32/Zbot.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {0f b6 85 4f fd ff ff 8b 8d 1c fc ff ff 81 e1 ff ff 00 00 0f b7 c9 81 e1 ff 00 00 00 0f b6 c9 33 c1 8b 8d 54 fd ff ff 88 84 0d 4c fc ff ff } //03 00 
		$a_81_1 = {50 74 73 63 61 6e 2e 65 78 65 } //00 00  Ptscan.exe
	condition:
		any of ($a_*)
 
}