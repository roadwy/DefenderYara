
rule Backdoor_Win32_Wecoym_A{
	meta:
		description = "Backdoor:Win32/Wecoym.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 8b fa 88 5c 24 14 8a cb 33 d2 89 4c 24 18 8b f5 42 8a 06 3c 2e 74 28 3c 3e 74 24 3c 36 74 20 3c 26 74 1c 3c 64 74 18 } //1
		$a_01_1 = {85 c0 75 0a 39 47 08 74 05 ff 77 08 eb 2b 53 68 } //1
		$a_01_2 = {5f 35 70 65 63 6a 6b 6a 6b 6c 74 5f } //1 _5pecjkjklt_
		$a_01_3 = {77 65 79 2e 63 6f 6d 00 7e } //1
		$a_01_4 = {50 52 49 56 4d 53 47 00 32 4b 00 00 58 50 00 00 32 4b 33 00 56 53 00 00 32 4b 38 00 57 37 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}