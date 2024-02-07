
rule Trojan_Win32_BHO_A{
	meta:
		description = "Trojan:Win32/BHO.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_1 = {73 65 72 2e 65 78 65 } //01 00  ser.exe
		$a_00_2 = {69 75 70 2e 65 78 65 } //01 00  iup.exe
		$a_00_3 = {62 68 6f 2e 64 6c 6c } //01 00  bho.dll
		$a_00_4 = {70 6c 61 79 2e 64 6c 6c } //01 00  play.dll
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_00_6 = {45 78 70 6c 6f 72 65 72 5c 52 75 6e } //01 00  Explorer\Run
		$a_00_7 = {66 75 63 6b 79 6f 75 } //01 00  fuckyou
		$a_00_8 = {25 73 2c 41 6c 77 61 79 73 } //01 00  %s,Always
		$a_00_9 = {6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b } //01 00  microsoft_lock
		$a_00_10 = {5c 72 65 67 73 76 72 33 32 2e 65 78 65 } //01 00  \regsvr32.exe
		$a_00_11 = {2e 74 78 74 } //01 00  .txt
		$a_00_12 = {2e 62 6d 70 } //01 00  .bmp
		$a_00_13 = {73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 } //01 00  sysoption.ini
		$a_00_14 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //01 00  \\.\PhysicalDrive%d
		$a_00_15 = {77 69 6e 69 6f 2e 73 79 73 } //01 00  winio.sys
		$a_00_16 = {5c 5c 2e 5c 53 63 73 69 25 64 3a } //01 00  \\.\Scsi%d:
		$a_02_17 = {51 8a 44 24 03 53 56 57 a2 90 01 01 c5 40 00 bf 90 01 01 c0 40 00 83 c9 ff 33 c0 33 d2 33 f6 f2 ae f7 d1 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}