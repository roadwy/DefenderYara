
rule TrojanDropper_O97M_Obfuse_OSP_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.OSP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 72 74 64 20 3d 20 22 57 22 } //01 00  Strtd = "W"
		$a_01_1 = {53 65 74 20 50 5f 4f 6c 37 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 53 74 72 74 64 20 26 20 72 6f 63 32 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 26 20 22 2e 22 20 26 20 72 6f 63 33 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 29 } //01 00  Set P_Ol7 = CreateObject(Strtd & roc2.ControlTipText & "." & roc3.ControlTipText)
		$a_01_2 = {4d 69 6b 65 43 68 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 20 26 20 22 70 69 6e 22 20 26 20 22 2e 6a 22 20 26 20 72 6f 63 34 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //01 00  MikeCh = UserForm1.Label1.Caption & "pin" & ".j" & roc4.ControlTipText
		$a_01_3 = {4f 70 65 6e 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6c 6f 61 64 2e 74 78 74 22 20 46 6f 72 20 42 69 6e 61 72 79 20 4c 6f 63 6b 20 52 65 61 64 20 57 72 69 74 65 20 41 73 20 23 } //01 00  Open "C:\Users\Public\Documents\load.txt" For Binary Lock Read Write As #
		$a_01_4 = {4e 61 6d 65 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 20 41 73 20 4d 69 6b 65 43 68 } //01 00  Name UserForm1.Label1.Caption As MikeCh
		$a_01_5 = {4d 65 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 20 3d 20 4d 69 6b 65 43 68 } //01 00  Me.Label1.Caption = MikeCh
		$a_01_6 = {72 6f 63 34 2e 43 61 70 74 69 6f 6e 20 3d 20 43 68 72 28 33 34 29 } //01 00  roc4.Caption = Chr(34)
		$a_01_7 = {4d 73 67 42 6f 78 20 72 6f 63 32 2e 43 61 70 74 69 6f 6e } //00 00  MsgBox roc2.Caption
	condition:
		any of ($a_*)
 
}