
rule PWS_Win32_Lmir{
	meta:
		description = "PWS:Win32/Lmir,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_02_0 = {83 c4 18 88 9c 3d f3 fe ff ff ff 75 fc 53 68 ff 0f 1f 00 ff 15 90 01 04 8b f8 3b fb 74 11 53 57 ff 15 90 01 04 6a ff 57 ff 15 90 00 } //01 00 
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_00_2 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00  AVP.Product_Notification
		$a_00_4 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //00 00  AVP.AlertDialog
	condition:
		any of ($a_*)
 
}