
rule Backdoor_Win32_Advo{
	meta:
		description = "Backdoor:Win32/Advo,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 69 64 4d 65 73 73 61 67 65 00 } //1
		$a_01_1 = {61 60 33 c0 cd 2e } //1
		$a_01_2 = {c6 45 e1 6d c6 45 e2 73 c6 45 e3 61 c6 45 e4 63 c6 45 e5 6d c6 45 e6 33 c6 45 e7 32 c6 45 e8 2e c6 45 e9 64 c6 45 ea 72 c6 45 eb 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}