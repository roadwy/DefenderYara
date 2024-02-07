
rule Trojan_Win32_Dridex_WE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.WE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //03 00  LdrGetProcedureA
		$a_81_1 = {74 65 73 74 73 76 69 63 74 6f 72 69 61 34 62 65 6e 63 68 6d 61 72 6b 73 2c 73 75 62 6d 69 73 73 69 6f 6e 73 } //03 00  testsvictoria4benchmarks,submissions
		$a_81_2 = {43 72 65 61 74 65 48 61 74 63 68 42 72 75 73 68 } //03 00  CreateHatchBrush
		$a_81_3 = {47 65 74 52 61 6e 64 6f 6d 52 67 6e } //03 00  GetRandomRgn
		$a_81_4 = {46 6c 61 73 68 4c 73 74 61 6e 64 61 72 64 73 75 63 68 35 53 74 61 62 6c 65 } //03 00  FlashLstandardsuch5Stable
		$a_81_5 = {44 65 66 44 6c 67 50 72 6f 63 57 } //03 00  DefDlgProcW
		$a_81_6 = {4c 6f 63 6b 57 69 6e 64 6f 77 55 70 64 61 74 65 } //00 00  LockWindowUpdate
	condition:
		any of ($a_*)
 
}