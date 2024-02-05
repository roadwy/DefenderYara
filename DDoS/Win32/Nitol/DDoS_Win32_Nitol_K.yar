
rule DDoS_Win32_Nitol_K{
	meta:
		description = "DDoS:Win32/Nitol.K,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6a 64 66 77 6b 65 79 } //01 00 
		$a_01_1 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 } //02 00 
		$a_01_2 = {83 c0 03 33 d2 0f af c6 f7 74 24 } //03 00 
		$a_01_3 = {33 33 39 32 31 30 33 35 2e 66 33 33 32 32 2e 6f 72 67 } //00 00 
		$a_00_4 = {5d 04 00 00 d2 66 03 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}