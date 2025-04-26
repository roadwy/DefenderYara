
rule Backdoor_Win32_Zegost_DY_bit{
	meta:
		description = "Backdoor:Win32/Zegost.DY!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 98 cb ee 7d 3a 5d 20 25 73 0d 0a 5b 95 72 e9 67 3a 5d 25 64 2d 25 64 2d 25 64 20 20 25 64 3a 25 64 3a 25 64 0d 0a 00 } //2
		$a_01_1 = {5c b3 cc d0 f2 5c c6 f4 b6 af 5c 73 65 72 76 65 72 2e 65 78 65 00 } //2
		$a_01_2 = {5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 65 72 76 65 72 2e 65 78 65 } //2 \Programs\Startup\server.exe
		$a_01_3 = {5c 73 76 63 63 68 6f 73 74 2e 65 78 65 00 } //2
		$a_01_4 = {2e 3f 41 56 43 53 63 72 65 65 6e 53 70 79 40 40 } //1 .?AVCScreenSpy@@
		$a_01_5 = {3f 41 56 43 4b 65 79 62 6f 61 72 64 4d 61 6e 61 67 65 72 40 40 } //1 ?AVCKeyboardManager@@
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}