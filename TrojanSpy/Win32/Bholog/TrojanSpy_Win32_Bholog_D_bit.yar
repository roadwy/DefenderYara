
rule TrojanSpy_Win32_Bholog_D_bit{
	meta:
		description = "TrojanSpy:Win32/Bholog.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 00 77 00 6f 00 72 00 6b 00 67 00 72 00 61 00 63 00 65 00 00 00 } //5
		$a_01_1 = {5b 00 50 00 41 00 53 00 54 00 45 00 5d 00 } //1 [PASTE]
		$a_01_2 = {5b 00 2b 00 2b 00 2b 00 2b 00 5d 00 } //1 [++++]
		$a_01_3 = {5b 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 5d 00 } //1 [Passwords]
		$a_01_4 = {5b 00 53 00 53 00 53 00 53 00 53 00 5d 00 } //1 [SSSSS]
		$a_01_5 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 } //1 cmd.exe /c
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}