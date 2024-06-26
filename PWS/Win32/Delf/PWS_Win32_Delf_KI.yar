
rule PWS_Win32_Delf_KI{
	meta:
		description = "PWS:Win32/Delf.KI,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 72 69 6b 65 4f 75 74 } //01 00  StrikeOut
		$a_00_1 = {48 6f 74 4c 69 67 68 74 } //02 00  HotLight
		$a_00_2 = {67 73 6d 74 70 31 38 35 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //02 00  gsmtp185.google.com
		$a_00_3 = {25 30 25 32 25 34 25 36 25 38 25 3a 25 3c 25 3e 25 40 25 42 25 45 25 47 25 49 25 } //02 00  %0%2%4%6%8%:%<%>%@%B%E%G%I%
		$a_00_4 = {6d 73 6e 6c 69 73 74 2e 74 78 74 } //03 00  msnlist.txt
		$a_02_5 = {8b 80 00 03 00 00 05 90 90 00 00 00 ba 03 00 00 00 e8 90 01 04 68 90 01 04 8b 45 fc 8b 80 00 03 00 00 8b 48 6c b2 01 a1 90 01 04 e8 90 01 04 8b 45 fc 8b 80 fc 02 00 00 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}