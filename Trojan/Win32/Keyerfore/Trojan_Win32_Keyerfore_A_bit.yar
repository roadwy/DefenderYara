
rule Trojan_Win32_Keyerfore_A_bit{
	meta:
		description = "Trojan:Win32/Keyerfore.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 23 23 20 53 74 61 72 74 65 64 20 6c 6f 67 67 69 6e 67 20 61 74 3a } //01 00  ### Started logging at:
		$a_01_1 = {25 61 70 70 64 61 74 61 25 5c 73 76 63 68 6f 73 74 } //01 00  %appdata%\svchost
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_3 = {66 74 70 2e 90 02 10 2e 63 6f 6d 00 55 53 45 52 20 90 02 20 0d 0a 00 50 41 53 53 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 f4 
	condition:
		any of ($a_*)
 
}