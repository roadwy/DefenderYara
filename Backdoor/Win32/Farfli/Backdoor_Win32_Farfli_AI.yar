
rule Backdoor_Win32_Farfli_AI{
	meta:
		description = "Backdoor:Win32/Farfli.AI,SIGNATURE_TYPE_PEHSTR_EXT,ffffffcd 00 ffffffb9 00 08 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c } //100
		$a_01_1 = {c6 45 ee 69 c6 45 ef 73 c6 45 f0 52 c6 45 f1 61 c6 45 f2 74 } //30
		$a_01_2 = {8d 45 ec c6 45 ce 55 c6 45 cf aa 53 53 6a 03 53 6a 03 68 00 00 00 c0 50 c6 45 ec 5c } //30
		$a_01_3 = {c6 45 df 6e c6 45 e0 65 c6 45 e1 74 c6 45 e2 20 c6 45 e3 73 c6 45 e4 74 c6 45 e5 6f c6 45 e6 70 } //30
		$a_01_4 = {c6 45 e0 23 c6 45 e1 33 c6 45 e2 32 c6 45 e3 37 c6 45 e4 37 c6 45 e5 30 88 5d e6 ff 15 } //25
		$a_01_5 = {c6 45 a2 6e c6 45 a3 65 c6 45 a4 2e c6 45 a5 70 c6 45 a6 62 c6 45 a7 6b } //25
		$a_01_6 = {c6 45 f8 6e c6 45 f9 5c c6 45 fa 52 c6 45 fb 75 c6 45 fc 6e } //25
		$a_01_7 = {c6 45 f4 43 c6 45 f5 68 c6 45 f6 69 c6 45 f7 63 c6 45 f8 6b } //25
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*30+(#a_01_2  & 1)*30+(#a_01_3  & 1)*30+(#a_01_4  & 1)*25+(#a_01_5  & 1)*25+(#a_01_6  & 1)*25+(#a_01_7  & 1)*25) >=185
 
}