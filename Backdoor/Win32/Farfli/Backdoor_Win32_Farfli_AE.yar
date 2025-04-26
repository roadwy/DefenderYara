
rule Backdoor_Win32_Farfli_AE{
	meta:
		description = "Backdoor:Win32/Farfli.AE,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 13 01 06 00 00 "
		
	strings :
		$a_01_0 = {c6 85 5c fe ff ff 4d c6 85 5d fe ff ff 58 c6 85 5e fe ff ff 57 c6 85 5f fe ff ff 4c c6 85 60 fe ff ff 56 c6 85 61 fe ff ff 49 } //100
		$a_01_1 = {75 07 32 c0 e9 a9 01 00 00 c6 45 ec 05 c6 45 ed 01 c6 45 ee 00 c6 45 ef 01 8b 95 6c fc ff ff } //100
		$a_01_2 = {c6 45 90 70 c6 45 91 62 c6 45 92 6b c6 45 93 5c c6 45 94 72 c6 45 95 61 c6 45 96 73 } //50
		$a_01_3 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //25
		$a_01_4 = {5b 43 2e 61 2e 70 2e 73 2e 4c 2e 6f 2e 63 2e 6b 2e 5d } //25 [C.a.p.s.L.o.c.k.]
		$a_01_5 = {c6 85 64 ff ff ff 00 b8 01 00 00 00 b8 ff ff ff ff 90 90 c6 85 } //25
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*50+(#a_01_3  & 1)*25+(#a_01_4  & 1)*25+(#a_01_5  & 1)*25) >=275
 
}