
rule Worm_Win32_Casmondu_A{
	meta:
		description = "Worm:Win32/Casmondu.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 4d 00 6f 00 6e 00 65 00 79 00 2e 00 76 00 62 00 70 00 } //01 00  MyMoney.vbp
		$a_01_1 = {75 00 73 00 65 00 72 00 63 00 61 00 73 00 68 00 2e 00 63 00 6f 00 6d 00 } //01 00  usercash.com
		$a_02_2 = {47 00 61 00 72 00 64 00 65 00 6e 00 44 00 65 00 66 00 65 00 6e 00 73 00 65 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 90 02 33 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 90 00 } //01 00 
		$a_01_3 = {74 6d 72 49 6e 66 65 63 74 } //01 00  tmrInfect
		$a_01_4 = {74 6d 72 4d 6f 6e 65 79 } //00 00  tmrMoney
	condition:
		any of ($a_*)
 
}