
rule Virus_Win32_Xorer_gen_B{
	meta:
		description = "Virus:Win32/Xorer.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 43 49 20 50 72 6f 67 72 61 00 } //01 00 
		$a_00_1 = {5c 63 6f 6d 5c 6c 73 61 73 73 2e 65 78 65 } //01 00  \com\lsass.exe
		$a_00_2 = {30 33 37 35 38 39 2e 6c 6f 67 } //01 00  037589.log
		$a_00_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 64 20 2f 73 20 2f 71 20 22 } //01 00  cmd.exe /c rd /s /q "
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 53 75 70 65 72 48 69 64 64 65 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden
		$a_00_5 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4d 69 6e 69 6d 61 6c 5c 7b 34 44 33 36 45 39 36 37 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d } //01 00  SYSTEM\ControlSet001\Control\SafeBoot\Minimal\{4D36E967-E325-11CE-BFC1-08002BE10318}
		$a_00_6 = {00 68 6f 6f 6b 2e 64 6c 6c } //01 00 
		$a_01_7 = {49 6e 73 74 61 6c 6c 48 4f 4f 4b } //01 00  InstallHOOK
		$a_00_8 = {33 36 30 73 61 66 65 } //01 00  360safe
		$a_00_9 = {66 61 63 65 6c 65 73 73 77 6e 64 70 72 6f 63 } //01 00  facelesswndproc
		$a_00_10 = {62 69 74 64 65 66 65 6e 64 65 72 } //00 00  bitdefender
	condition:
		any of ($a_*)
 
}