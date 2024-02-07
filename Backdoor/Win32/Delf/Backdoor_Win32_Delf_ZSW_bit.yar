
rule Backdoor_Win32_Delf_ZSW_bit{
	meta:
		description = "Backdoor:Win32/Delf.ZSW!bit,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //0a 00  Software\Microsoft\Windows\CurrentVersion\Run\
		$a_03_1 = {77 69 6e 64 69 72 90 02 10 70 72 6f 67 72 61 6d 90 02 10 50 72 6f 67 72 61 6d 46 69 6c 65 73 90 00 } //0a 00 
		$a_03_2 = {5b 50 61 67 65 20 44 6f 77 6e 5d 90 02 10 5b 45 6e 64 5d 90 02 10 5b 48 6f 6d 65 5d 90 02 10 5b 4c 65 66 74 5d 90 02 10 5b 55 70 5d 90 00 } //01 00 
		$a_01_3 = {73 64 6e 3d } //01 00  sdn=
		$a_01_4 = {73 63 6f 3d } //01 00  sco=
		$a_01_5 = {73 6e 61 3d } //01 00  sna=
		$a_01_6 = {73 70 61 3d } //01 00  spa=
		$a_01_7 = {73 6c 6e 3d } //01 00  sln=
		$a_01_8 = {73 70 6f 3d } //00 00  spo=
		$a_00_9 = {5d 04 00 00 e9 7a 03 80 5c 25 00 00 ea 7a 03 80 00 00 01 00 08 00 0f 00 } //ac 21 
	condition:
		any of ($a_*)
 
}