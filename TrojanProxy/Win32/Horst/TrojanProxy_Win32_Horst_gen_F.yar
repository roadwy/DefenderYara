
rule TrojanProxy_Win32_Horst_gen_F{
	meta:
		description = "TrojanProxy:Win32/Horst.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 43 44 32 2d 32 33 44 30 2d 42 41 43 34 2d } //1 ECD2-23D0-BAC4-
		$a_02_1 = {2e 6e 76 73 76 63 ?? 00 } //1
		$a_00_2 = {77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 ws\CurrentVersion\Run
		$a_00_3 = {25 73 00 6e 76 00 } //1 猥渀v
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}