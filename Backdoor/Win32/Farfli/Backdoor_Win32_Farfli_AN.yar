
rule Backdoor_Win32_Farfli_AN{
	meta:
		description = "Backdoor:Win32/Farfli.AN,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbe 00 ffffffaa 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c } //100
		$a_01_1 = {b9 00 5c 26 05 33 d2 8b f9 8b f0 f7 f7 33 d2 89 45 08 8b c6 f7 f1 b9 80 ee 36 00 } //50
		$a_01_2 = {a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c 53 74 61 72 74 75 70 5c 68 61 6f 35 36 37 2e 65 78 65 } //20
		$a_01_3 = {c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c c6 45 f9 6f } //20
		$a_01_4 = {c6 45 c4 4b c6 45 c5 65 c6 45 c6 79 c6 45 90 41 c6 45 91 44 c6 45 92 56 } //20
		$a_01_5 = {0f b7 d0 0f af 55 0c 8b 4d 10 83 c2 1f c1 fa 03 83 e2 fc c7 06 28 00 00 00 0f af d1 83 f8 10 } //20
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20) >=170
 
}