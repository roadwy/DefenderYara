
rule Ransom_Win32_Winshulock_A{
	meta:
		description = "Ransom:Win32/Winshulock.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {c7 04 01 01 01 01 01 83 c1 04 3b 4d 90 01 01 72 f1 59 58 ba 02 00 00 00 8b 45 90 01 01 e8 90 01 04 8b d8 83 fb ff 74 2f 90 00 } //02 00 
		$a_00_1 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 30 30 20 2d 63 20 65 72 72 6f 72 20 3e 20 6e 75 6c } //01 00  shutdown -s -t 00 -c error > nul
		$a_02_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 36 90 02 0c 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 37 90 00 } //01 00 
		$a_01_3 = {57 69 6e 55 70 64 61 74 65 } //00 00  WinUpdate
		$a_00_4 = {5d 04 00 00 } //57 32 
	condition:
		any of ($a_*)
 
}