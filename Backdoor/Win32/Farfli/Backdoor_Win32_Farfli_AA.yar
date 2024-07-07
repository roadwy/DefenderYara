
rule Backdoor_Win32_Farfli_AA{
	meta:
		description = "Backdoor:Win32/Farfli.AA,SIGNATURE_TYPE_PEHSTR_EXT,36 01 0e 01 0a 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 5c c6 45 e9 6f c6 45 ea 75 c6 45 eb 72 c6 45 ec 6c } //100
		$a_01_1 = {83 c4 0c c6 85 62 ff ff ff 55 c6 85 63 ff ff ff aa 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 c0 } //100
		$a_01_2 = {c6 85 8d fe ff ff 53 c6 85 8e fe ff ff 65 c6 85 8f fe ff ff 72 c6 85 90 fe ff ff 76 } //50
		$a_01_3 = {74 2e 83 bd f8 fb ff ff ff 7e 25 83 bd b4 fb ff ff 40 7e 1c 83 bd b4 fb ff ff 5b 7d 13 } //50
		$a_01_4 = {ff 95 ac fb ff ff e9 69 fd ff ff e9 a8 fc ff ff 33 c0 5f 8b e5 5d c2 04 00 } //50
		$a_01_5 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //10
		$a_01_6 = {c6 45 f0 63 c6 45 f1 61 c6 45 f2 6f c6 45 f3 6e c6 45 f4 66 c6 45 f5 7a c6 45 f6 32 } //30
		$a_01_7 = {77 6f 77 2e 65 78 65 00 74 77 32 2e 65 78 65 } //10
		$a_01_8 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //5 <H1>403 Forbidden</H1>
		$a_01_9 = {74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 38 38 38 38 2f 69 70 2e 74 78 74 } //5 ttp://127.0.0.1:8888/ip.txt
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*50+(#a_01_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*10+(#a_01_6  & 1)*30+(#a_01_7  & 1)*10+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=270
 
}