
rule Backdoor_Win32_Farfli_AJ{
	meta:
		description = "Backdoor:Win32/Farfli.AJ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe1 00 ffffffc8 00 08 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c } //100
		$a_01_1 = {6a 14 ff d3 66 85 c0 74 20 83 7d f8 00 7d 30 83 fe 40 7e 15 83 fe 5b } //50
		$a_01_2 = {c6 45 ec 5c c6 45 ed 6f c6 45 ee 75 80 38 1e c6 45 ef 72 c6 45 f0 6c } //30
		$a_01_3 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //30
		$a_01_4 = {74 0b 66 81 bd ec fb ff ff 4d 5a 75 22 8d 45 ec 56 } //25
		$a_01_5 = {c6 45 ec 46 c6 45 ed 57 c6 45 ee 4b c6 45 ef 4a } //25
		$a_01_6 = {c6 45 f8 6e c6 45 f9 5c c6 45 fa 52 c6 45 fb 75 c6 45 fc 6e } //25
		$a_01_7 = {c6 45 e6 55 c6 45 e7 aa 53 53 6a 03 53 6a 03 68 00 00 00 c0 } //25
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*30+(#a_01_3  & 1)*30+(#a_01_4  & 1)*25+(#a_01_5  & 1)*25+(#a_01_6  & 1)*25+(#a_01_7  & 1)*25) >=200
 
}