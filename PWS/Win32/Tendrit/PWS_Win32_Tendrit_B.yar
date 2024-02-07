
rule PWS_Win32_Tendrit_B{
	meta:
		description = "PWS:Win32/Tendrit.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 90 01 04 80 f1 90 01 01 88 8c 05 90 01 04 40 83 f8 40 72 ea e8 90 00 } //01 00 
		$a_01_1 = {63 73 73 2e 61 73 68 78 3f } //01 00  css.ashx?
		$a_01_2 = {70 6f 6c 69 63 79 72 65 66 3f } //01 00  policyref?
		$a_01_3 = {32 4b 33 2e 25 73 } //00 00  2K3.%s
	condition:
		any of ($a_*)
 
}