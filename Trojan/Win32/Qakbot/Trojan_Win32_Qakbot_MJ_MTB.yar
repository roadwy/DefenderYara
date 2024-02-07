
rule Trojan_Win32_Qakbot_MJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {e0 8b 45 e0 dc 49 01 00 74 25 e9 01 54 31 05 83 78 0c 00 74 45 ba 40 d8 8b 4d fc e9 9b 3b 05 } //02 00 
		$a_01_1 = {57 69 6e 64 } //02 00  Wind
		$a_01_2 = {53 5a 31 33 64 65 66 61 75 6c 74 43 6f 6e 66 69 67 76 } //02 00  SZ13defaultConfigv
		$a_01_3 = {53 5a 31 39 4b 43 4f 4e 46 49 47 5f 57 49 44 47 45 54 53 5f 4c 4f 47 76 } //02 00  SZ19KCONFIG_WIDGETS_LOGv
		$a_01_4 = {53 5a 4e 31 30 4b 54 69 70 44 69 61 6c 6f 67 44 30 45 76 } //02 00  SZN10KTipDialogD0Ev
		$a_01_5 = {53 5a 4e 31 32 4b 43 6f 64 65 63 41 63 74 69 6f 6e 44 30 45 76 } //00 00  SZN12KCodecActionD0Ev
	condition:
		any of ($a_*)
 
}