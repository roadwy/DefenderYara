
rule PWS_Win32_Frethog_B{
	meta:
		description = "PWS:Win32/Frethog.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 12 00 09 00 00 03 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 55 4e } //04 00  Windows\CurrentVersion\RUN
		$a_00_1 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 47 } //04 00  AVP.AlertDialoG
		$a_01_2 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 } //03 00 
		$a_00_3 = {25 73 20 25 63 25 73 25 63 25 64 } //03 00  %s %c%s%c%d
		$a_00_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //03 00  explorer.exe
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //02 00  WriteProcessMemory
		$a_00_6 = {57 57 68 01 02 00 00 53 ff d6 57 57 68 02 02 00 00 53 ff d6 } //02 00 
		$a_02_7 = {68 01 02 00 00 90 01 01 ff d6 90 01 02 68 02 02 00 00 ff 75 fc ff d6 68 90 00 } //01 00 
		$a_00_8 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //00 00  LoadResource
	condition:
		any of ($a_*)
 
}