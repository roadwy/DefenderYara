
rule PWS_Win32_PWSteal_L{
	meta:
		description = "PWS:Win32/PWSteal.L,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_02_0 = {85 c0 0f 84 ?? ?? 00 00 b9 10 00 00 00 b8 90 90 90 90 90 90 90 90 8d bc 24 ?? 00 00 00 f3 ab 8d 84 24 ?? ?? 00 00 8d 8c 24 ?? 00 00 00 } //10
		$a_00_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4c 73 61 00 00 00 00 4c 73 61 50 69 64 } //10
		$a_00_2 = {5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d } //10 [%02d/%02d/%d %02d:%02d:%02d]
		$a_02_3 = {44 6f 6d 61 69 6e 3a [0-05] 25 53 } //1
		$a_02_4 = {55 73 65 72 3a [0-05] 25 53 } //1
		$a_02_5 = {50 61 73 73 77 6f 72 64 3a [0-05] 25 53 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=31
 
}