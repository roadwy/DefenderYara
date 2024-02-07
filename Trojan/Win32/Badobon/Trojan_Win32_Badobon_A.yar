
rule Trojan_Win32_Badobon_A{
	meta:
		description = "Trojan:Win32/Badobon.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 32 67 75 61 72 64 2e 65 78 65 } //01 00  a2guard.exe
		$a_01_1 = {70 63 74 73 47 75 69 2e 65 78 65 } //01 00  pctsGui.exe
		$a_01_2 = {4e 6f 72 6d 61 6e 5f 4d 61 6c 77 61 72 65 5f 43 6c 65 61 6e 65 72 2e 65 78 65 } //01 00  Norman_Malware_Cleaner.exe
		$a_01_3 = {46 69 72 65 77 61 6c 6c 47 55 49 2e 65 78 65 } //05 00  FirewallGUI.exe
		$a_03_4 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 90 02 10 42 41 53 53 5f 90 00 } //05 00 
		$a_03_5 = {41 64 6f 62 65 90 02 10 46 6c 61 73 68 90 02 10 54 65 6d 70 90 02 10 49 6e 69 74 90 02 10 4c 6f 67 6f 6e 90 02 10 55 70 64 61 74 65 90 02 10 49 44 4d 90 00 } //00 00 
		$a_00_6 = {5d 04 00 00 ac 7d } //03 80 
	condition:
		any of ($a_*)
 
}