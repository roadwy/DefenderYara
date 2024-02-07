
rule Backdoor_Win32_Pabcares_A_dha{
	meta:
		description = "Backdoor:Win32/Pabcares.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 70 63 77 75 6d 2e 50 63 77 43 6c 65 61 72 43 6f 75 6e 74 65 72 53 65 74 53 65 63 75 72 69 74 79 } //01 00  c:\windows\system32\pcwum.PcwClearCounterSetSecurity
		$a_00_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6b 74 6d 77 33 32 2e 52 6f 6c 6c 66 6f 72 77 61 72 64 54 72 61 6e 73 61 63 74 69 6f 6e 4d 61 6e 61 67 65 72 } //01 00  c:\windows\system32\ktmw32.RollforwardTransactionManager
		$a_00_2 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 61 70 70 64 61 74 61 5c 6c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 49 4e 65 74 43 61 63 68 65 5c 43 61 63 68 65 } //01 00  c:\users\public\appdata\local\Microsoft\Windows\INetCache\Cache
		$a_03_3 = {77 65 62 65 90 01 03 90 02 03 6e 67 69 6e 90 00 } //01 00 
		$a_03_4 = {6f 6e 74 65 66 c7 90 01 02 6e 74 90 00 } //01 00 
		$a_01_5 = {77 33 77 70 48 90 01 04 c7 44 90 01 02 2e 65 78 65 90 00 } //01 00 
		$a_01_6 = {f5 d7 c4 d2 e5 d3 d5 c3 c4 df c2 cf f8 c3 db d4 } //00 00 
	condition:
		any of ($a_*)
 
}