
rule Trojan_Win32_Trickbot_N{
	meta:
		description = "Trojan:Win32/Trickbot.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 45 78 70 6c 6f 69 74 44 62 5c } //01 00  C:\Users\ExploitDb\
		$a_01_1 = {73 68 65 6c 6c 63 6f 64 65 5f 6d 61 69 6e 90 } //01 00 
		$a_01_2 = {54 6e 52 56 62 6d 31 68 63 46 5a 70 5a 58 64 50 5a 6c 4e 6c 59 33 52 70 62 32 34 3d } //01 00  TnRVbm1hcFZpZXdPZlNlY3Rpb24=
		$a_01_3 = {68 75 6b 6d 6e 6a 75 66 65 77 67 6a 6f 67 68 75 69 67 6f 68 76 62 74 79 73 6f 67 68 67 74 79 } //00 00  hukmnjufewgjoghuigohvbtysoghgty
	condition:
		any of ($a_*)
 
}