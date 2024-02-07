
rule Backdoor_Win32_Morix_A{
	meta:
		description = "Backdoor:Win32/Morix.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 78 04 02 01 00 00 0f 85 90 01 01 00 00 00 8b 4d 90 01 01 83 79 08 7f 77 90 01 01 8b 55 90 01 01 83 7a 08 14 90 00 } //03 00 
		$a_03_1 = {8b 55 08 03 55 90 01 01 0f be 02 83 f0 62 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //01 00 
		$a_00_2 = {5c 73 74 61 72 74 75 70 5c 33 36 30 74 72 61 79 2e 65 78 65 } //01 00  \startup\360tray.exe
		$a_00_3 = {5f 6b 61 73 70 65 72 73 6b 79 } //01 00  _kaspersky
		$a_00_4 = {00 5c 6b 65 79 6c 6f 67 2e 64 61 74 00 } //01 00 
		$a_00_5 = {00 45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 00 } //01 00 
		$a_00_6 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 52 44 50 54 63 70 } //00 00  CurrentControlSet\Control\Terminal Server\RDPTcp
	condition:
		any of ($a_*)
 
}