
rule Backdoor_Win32_Bifrose_IN{
	meta:
		description = "Backdoor:Win32/Bifrose.IN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 76 69 65 77 50 72 6f 63 65 73 73 2e 6a 73 00 } //1 瘀敩偷潲散獳樮s
		$a_00_1 = {00 61 64 64 52 65 67 69 74 65 6d 2e 68 74 6d 00 } //1
		$a_01_2 = {c6 45 f5 3e eb 04 c6 45 f5 3f 0f b6 45 f6 83 f8 40 7e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}