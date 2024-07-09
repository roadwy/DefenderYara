
rule PWS_Win32_Tendrit_B{
	meta:
		description = "PWS:Win32/Tendrit.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ?? ?? 40 83 f8 40 72 ea e8 } //2
		$a_01_1 = {63 73 73 2e 61 73 68 78 3f } //1 css.ashx?
		$a_01_2 = {70 6f 6c 69 63 79 72 65 66 3f } //1 policyref?
		$a_01_3 = {32 4b 33 2e 25 73 } //1 2K3.%s
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}