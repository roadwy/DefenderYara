
rule TrojanClicker_Win32_Cutwail_A{
	meta:
		description = "TrojanClicker:Win32/Cutwail.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 63 6b 20 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 Click Verification
		$a_01_1 = {6c 69 6e 6b 70 72 6f 62 } //1 linkprob
		$a_01_2 = {6c 6f 67 5f 66 69 6c 74 65 72 5f 75 72 6c } //1 log_filter_url
		$a_01_3 = {5c 5c 2e 5c 52 75 6e 74 69 6d 65 } //1 \\.\Runtime
		$a_00_4 = {32 31 36 2e 31 39 35 2e 35 35 2e 31 30 } //1 216.195.55.10
		$a_00_5 = {3d 45 57 59 42 59 75 01 46 8b c6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}