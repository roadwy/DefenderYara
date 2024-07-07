
rule Backdoor_Win32_FakOutl_SA_MSR{
	meta:
		description = "Backdoor:Win32/FakOutl.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 41 70 70 6c 79 53 65 74 74 69 6e 67 73 } //1 LogApplySettings
		$a_01_1 = {63 68 61 72 6c 65 73 65 65 64 77 61 72 64 73 2e 64 79 6e 61 6d 69 63 2d 64 6e 73 2e 6e 65 74 } //1 charleseedwards.dynamic-dns.net
		$a_01_2 = {3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 :\Windows\iexplore.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}