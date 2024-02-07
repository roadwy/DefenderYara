
rule Trojan_Win32_Qakbot_GEO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 5a 31 33 64 65 66 61 75 6c 74 43 6f 6e 66 69 67 76 } //01 00  SZ13defaultConfigv
		$a_01_1 = {53 5a 4e 31 30 4b 54 69 70 44 69 61 6c 6f 67 44 32 45 76 } //01 00  SZN10KTipDialogD2Ev
		$a_01_2 = {53 5a 4e 31 32 4b 43 6f 64 65 63 41 63 74 69 6f 6e 44 32 45 76 } //01 00  SZN12KCodecActionD2Ev
		$a_01_3 = {53 5a 4e 31 32 4b 54 69 70 44 61 74 61 62 61 73 65 37 50 72 69 76 61 74 65 37 61 64 64 54 69 70 73 45 52 4b 37 51 53 74 72 69 6e 67 } //01 00  SZN12KTipDatabase7Private7addTipsERK7QString
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {53 5a 4e 35 51 48 61 73 68 49 37 51 53 74 72 69 6e 67 50 37 51 57 69 64 67 65 74 45 31 33 64 75 70 6c 69 63 61 74 65 4e 6f 64 65 45 50 4e 39 51 48 61 73 68 44 61 74 61 34 4e 6f 64 65 45 50 76 } //00 00  SZN5QHashI7QStringP7QWidgetE13duplicateNodeEPN9QHashData4NodeEPv
	condition:
		any of ($a_*)
 
}