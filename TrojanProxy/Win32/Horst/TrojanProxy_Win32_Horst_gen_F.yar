
rule TrojanProxy_Win32_Horst_gen_F{
	meta:
		description = "TrojanProxy:Win32/Horst.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 43 44 32 2d 32 33 44 30 2d 42 41 43 34 2d } //01 00  ECD2-23D0-BAC4-
		$a_02_1 = {2e 6e 76 73 76 63 90 01 01 00 90 00 } //01 00 
		$a_00_2 = {77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  ws\CurrentVersion\Run
		$a_00_3 = {25 73 00 6e 76 00 } //00 00  猥渀v
	condition:
		any of ($a_*)
 
}