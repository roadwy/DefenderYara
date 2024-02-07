
rule Trojan_Win32_Delbat_B{
	meta:
		description = "Trojan:Win32/Delbat.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 00 73 65 6c 66 64 65 6c 00 2e 62 61 74 } //01 00 
		$a_01_1 = {64 65 6c 20 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 20 2a 2e 64 6c 6c 20 2f 71 } //01 00  del C:\windows\system32 *.dll /q
		$a_01_2 = {64 65 6c 20 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 20 2a 2e 73 79 73 20 2f 71 } //01 00  del C:\windows\system32 *.sys /q
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_01_4 = {50 00 75 00 72 00 70 00 6c 00 65 00 20 00 4a 00 75 00 6d 00 70 00 65 00 72 00 73 00 } //00 00  Purple Jumpers
	condition:
		any of ($a_*)
 
}