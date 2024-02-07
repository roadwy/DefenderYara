
rule Worm_Win32_Kolabc_C{
	meta:
		description = "Worm:Win32/Kolabc.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 41 4e 4d 41 4e 31 2e 30 } //01 00  LANMAN1.0
		$a_01_1 = {5c 5c 25 73 5c 70 69 70 65 5c 73 72 76 73 76 63 } //01 00  \\%s\pipe\srvsvc
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_3 = {5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //01 00  \Internet Account Manager\Accounts
		$a_01_4 = {41 76 65 72 61 67 65 5b 25 64 20 6b 62 69 74 2f 73 5d } //01 00  Average[%d kbit/s]
		$a_01_5 = {54 6f 74 61 6c 20 73 68 61 72 65 73 20 5b 25 73 3a 20 25 64 5d } //00 00  Total shares [%s: %d]
	condition:
		any of ($a_*)
 
}