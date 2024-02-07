
rule Trojan_Win32_Tnega_MW_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4d 00 4d 00 12 00 00 0a 00 "
		
	strings :
		$a_81_0 = {41 56 42 79 74 65 41 72 72 61 79 4f 77 6e 65 72 } //0a 00  AVByteArrayOwner
		$a_81_1 = {41 56 5f 63 6b 4c 6f 67 67 65 72 } //0a 00  AV_ckLogger
		$a_81_2 = {62 63 72 79 70 74 2e 64 6c 6c } //0a 00  bcrypt.dll
		$a_81_3 = {7a 65 65 4c 6f 67 2e 74 78 74 } //0a 00  zeeLog.txt
		$a_81_4 = {54 4f 4f 4c 5f 42 4c 4f 43 4b 5f 49 43 4f 4e } //0a 00  TOOL_BLOCK_ICON
		$a_81_5 = {49 6e 74 65 72 66 61 63 65 73 2e 53 68 65 6c 6c 45 78 74 65 6e 73 69 6f 6e 2e 4a 75 6d 70 4c 69 73 74 } //0a 00  Interfaces.ShellExtension.JumpList
		$a_81_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 43 50 4d } //01 00  SOFTWARE\Borland\Delphi\CPM
		$a_81_7 = {47 52 5f 43 4c 41 53 53 } //01 00  GR_CLASS
		$a_81_8 = {66 69 6c 65 2e 64 61 74 } //01 00  file.dat
		$a_81_9 = {62 61 73 65 36 34 75 72 6c } //01 00  base64url
		$a_81_10 = {72 65 67 4b 65 79 55 6e 6c 6f 63 6b } //01 00  regKeyUnlock
		$a_81_11 = {75 6e 6c 6f 63 6b 43 6f 64 65 } //01 00  unlockCode
		$a_81_12 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_81_13 = {49 6d 61 67 65 4c 69 73 74 5f 53 65 74 4f 76 65 72 6c 61 79 49 6d 61 67 65 } //01 00  ImageList_SetOverlayImage
		$a_81_14 = {43 72 65 61 74 65 50 69 70 65 } //01 00  CreatePipe
		$a_81_15 = {44 72 61 67 51 75 65 72 79 46 69 6c 65 57 } //01 00  DragQueryFileW
		$a_81_16 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //01 00  ShellExecuteW
		$a_81_17 = {52 65 67 69 73 74 65 72 44 72 61 67 44 72 6f 70 } //00 00  RegisterDragDrop
	condition:
		any of ($a_*)
 
}