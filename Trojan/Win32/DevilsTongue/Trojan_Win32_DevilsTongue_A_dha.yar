
rule Trojan_Win32_DevilsTongue_A_dha{
	meta:
		description = "Trojan:Win32/DevilsTongue.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {53 79 6d 49 6e 69 74 69 61 6c 69 7a 65 90 02 04 64 62 67 68 65 6c 70 2e 64 6c 6c 90 00 } //02 00 
		$a_03_1 = {64 00 62 00 67 00 48 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00 90 02 04 53 74 61 63 6b 57 61 6c 6b 36 34 90 00 } //01 00 
		$a_01_2 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6f 00 6c 00 64 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 } //03 00  windows.old\windows
		$a_00_3 = {8b 29 ee ed bd d3 cf bb 35 66 6c 63 3f ca ae 4a } //01 00 
		$a_01_4 = {53 4d 4e 65 77 2e 64 6c 6c } //02 00  SMNew.dll
		$a_01_5 = {b8 ff 15 00 00 66 39 41 fa 74 06 80 79 fb e8 } //00 00 
	condition:
		any of ($a_*)
 
}