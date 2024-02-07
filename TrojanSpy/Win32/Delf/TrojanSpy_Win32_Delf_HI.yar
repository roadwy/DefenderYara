
rule TrojanSpy_Win32_Delf_HI{
	meta:
		description = "TrojanSpy:Win32/Delf.HI,SIGNATURE_TYPE_PEHSTR,11 00 11 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  SOFTWARE\Borland\Delphi
		$a_01_1 = {28 59 75 6b 61 72 } //01 00  (Yukar
		$a_01_2 = {28 49 6e 73 65 72 74 29 20 } //01 00  (Insert) 
		$a_01_3 = {28 4e 75 6d 6c 6f 63 6b 29 20 } //01 00  (Numlock) 
		$a_01_4 = {28 43 74 72 6c 29 } //01 00  (Ctrl)
		$a_01_5 = {28 50 61 75 73 65 29 20 } //01 00  (Pause) 
		$a_01_6 = {7b 45 53 43 7d 20 } //01 00  {ESC} 
		$a_01_7 = {5c 77 69 6e 64 72 69 76 65 72 73 2e 6c 6f 67 } //01 00  \windrivers.log
		$a_01_8 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //01 00  \Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_9 = {6d 61 69 6c 73 65 6e 64 } //01 00  mailsend
		$a_01_10 = {61 63 69 6c 69 73 74 61 63 61 6c 69 73 } //01 00  acilistacalis
		$a_01_11 = {46 6f 72 6d 4b 65 79 44 6f 77 6e } //01 00  FormKeyDown
		$a_01_12 = {73 6d 74 70 5f 73 65 72 76 65 72 3d } //01 00  smtp_server=
		$a_01_13 = {73 6d 74 70 5f 75 73 65 72 3d } //01 00  smtp_user=
		$a_01_14 = {73 72 76 5f 66 69 6c 65 3d 77 69 6e 73 65 72 76 2e 65 78 65 } //01 00  srv_file=winserv.exe
		$a_01_15 = {42 61 63 6b 4c 6f 67 67 65 72 40 79 61 68 6f 6f 2e 63 6f 6d } //01 00  BackLogger@yahoo.com
		$a_01_16 = {42 61 63 6b 4c 6f 67 67 65 72 20 56 69 63 74 69 6d } //00 00  BackLogger Victim
	condition:
		any of ($a_*)
 
}