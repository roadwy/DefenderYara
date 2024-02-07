
rule VirTool_BAT_Subti_E{
	meta:
		description = "VirTool:BAT/Subti.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 72 65 2e 4b 65 79 6c 6f 67 67 65 72 } //01 00  Core.Keylogger
		$a_01_1 = {43 6f 72 65 2e 52 65 6d 6f 74 65 53 68 65 6c 6c } //01 00  Core.RemoteShell
		$a_01_2 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b 53 74 72 75 63 74 } //01 00  KeyboardHookStruct
		$a_01_3 = {53 65 6e 64 54 6f 54 61 72 67 65 74 53 65 72 76 65 72 } //01 00  SendToTargetServer
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //01 00  SELECT * FROM AntivirusProduct
		$a_01_5 = {65 00 63 00 68 00 6f 00 20 00 44 00 4f 00 4e 00 54 00 20 00 43 00 4c 00 4f 00 53 00 45 00 20 00 54 00 48 00 49 00 53 00 20 00 57 00 49 00 4e 00 44 00 4f 00 57 00 21 00 } //00 00  echo DONT CLOSE THIS WINDOW!
		$a_00_6 = {5d 04 00 } //00 5b 
	condition:
		any of ($a_*)
 
}