
rule PWS_Win32_Zengtu_A{
	meta:
		description = "PWS:Win32/Zengtu.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {57 58 59 5a 39 32 31 33 30 36 35 34 37 38 46 47 48 49 4a 4b 4c 4d 41 42 43 44 45 4e 4f 50 51 52 53 54 55 56 } //1 WXYZ9213065478FGHIJKLMABCDENOPQRSTUV
		$a_00_1 = {62 63 64 65 66 67 68 69 38 39 32 31 33 30 36 71 72 73 74 75 76 77 78 79 7a 35 34 37 6a 6b 6c 6d 6e 6f 70 61 } //1 bcdefghi8921306qrstuvwxyz547jklmnopa
		$a_01_2 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 PendingFileRenameOperations
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 AVP.Product_Notification
		$a_00_5 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //1 AVP.AlertDialog
		$a_01_6 = {62 67 74 7a 2e 64 6c 6c } //1 bgtz.dll
		$a_01_7 = {61 67 74 7a 2e 64 6c 6c } //1 agtz.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}