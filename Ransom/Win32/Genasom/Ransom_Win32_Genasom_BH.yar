
rule Ransom_Win32_Genasom_BH{
	meta:
		description = "Ransom:Win32/Genasom.BH,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //03 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 78 78 78 5f 76 69 64 65 6f 2e 65 78 65 } //01 00  C:\WINDOWS\system32\xxx_video.exe
		$a_01_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  C:\windows\system32\taskmgr.exe
		$a_01_3 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //02 00  Shell_TrayWnd
		$a_01_4 = {54 69 6d 65 72 31 54 69 6d 65 72 } //00 00  Timer1Timer
	condition:
		any of ($a_*)
 
}