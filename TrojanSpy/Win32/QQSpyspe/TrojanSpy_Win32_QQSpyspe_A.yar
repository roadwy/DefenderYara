
rule TrojanSpy_Win32_QQSpyspe_A{
	meta:
		description = "TrojanSpy:Win32/QQSpyspe.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {25 73 5c 7e 40 66 61 74 48 6a 25 64 2e 65 78 65 } //01 00  %s\~@fatHj%d.exe
		$a_00_1 = {25 73 5c 44 6f 77 6e 53 65 72 76 } //01 00  %s\DownServ
		$a_01_2 = {25 73 5c 70 61 61 6e 74 73 68 } //01 00  %s\paantsh
		$a_01_3 = {6e 65 77 71 71 72 65 63 } //01 00  newqqrec
		$a_00_4 = {64 69 72 6c 69 73 74 20 6d 6f 6e 69 74 6f 72 76 61 6c 75 65 3a 20 25 73 } //01 00  dirlist monitorvalue: %s
		$a_00_5 = {25 00 73 00 40 00 72 00 61 00 69 00 64 00 63 00 61 00 6c 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 74 00 77 00 2e 00 64 00 61 00 74 00 } //01 00  %s@raidcall.com.tw.dat
		$a_00_6 = {25 73 5c 25 73 5c 64 62 5c 6d 73 67 68 69 73 2e 69 6d 77 } //00 00  %s\%s\db\msghis.imw
		$a_00_7 = {80 10 00 } //00 8e 
	condition:
		any of ($a_*)
 
}