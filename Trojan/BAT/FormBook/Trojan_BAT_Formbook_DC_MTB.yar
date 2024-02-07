
rule Trojan_BAT_Formbook_DC_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 69 73 74 65 72 48 6f 6f 6b } //01 00  MisterHook
		$a_81_1 = {48 6f 6f 6b 4b 65 79 } //01 00  HookKey
		$a_81_2 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //01 00  keybd_event
		$a_81_3 = {6d 6f 75 73 65 5f 65 76 65 6e 74 } //01 00  mouse_event
		$a_81_4 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b 53 74 72 75 63 74 } //01 00  KeyboardHookStruct
		$a_81_5 = {4d 6f 75 73 65 48 6f 6f 6b 53 74 72 75 63 74 } //01 00  MouseHookStruct
		$a_81_6 = {50 61 74 68 54 6f 53 61 76 65 } //01 00  PathToSave
		$a_81_7 = {53 61 76 65 52 65 63 6f 72 64 54 6f 46 69 6c 65 } //00 00  SaveRecordToFile
	condition:
		any of ($a_*)
 
}