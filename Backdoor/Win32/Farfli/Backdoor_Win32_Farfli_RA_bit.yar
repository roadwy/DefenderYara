
rule Backdoor_Win32_Farfli_RA_bit{
	meta:
		description = "Backdoor:Win32/Farfli.RA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e1 63 c6 45 e2 2e c6 45 e3 63 c6 45 e4 63 c6 45 e5 32 c6 45 e6 35 c6 45 e7 79 c6 45 e8 72 c6 45 e9 2e c6 45 ea 6f } //1
		$a_01_1 = {53 79 73 74 65 6d 25 63 25 63 25 63 2e 65 78 65 } //1 System%c%c%c.exe
		$a_01_2 = {58 58 4f 4f 58 58 4f 4f 3a 25 73 7c 25 64 7c 25 64 7c 25 73 } //1 XXOOXXOO:%s|%d|%d|%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}