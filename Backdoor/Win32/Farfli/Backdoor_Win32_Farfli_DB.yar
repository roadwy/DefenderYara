
rule Backdoor_Win32_Farfli_DB{
	meta:
		description = "Backdoor:Win32/Farfli.DB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 e4 b8 4d 5a 00 00 c6 07 4d c6 47 01 5a 66 39 07 74 07 33 c0 e9 10 01 00 00 } //1
		$a_01_1 = {8a 14 01 80 ea 26 80 f2 29 88 14 01 41 3b ce 7c ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}