
rule TrojanProxy_Win32_VB_N{
	meta:
		description = "TrojanProxy:Win32/VB.N,SIGNATURE_TYPE_PEHSTR,47 00 47 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 43 00 53 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 76 00 62 00 70 00 } //50 ReCS\Server\Services.vbp
		$a_01_1 = {33 39 33 32 53 65 72 76 69 63 65 73 } //10 3932Services
		$a_01_2 = {36 00 39 00 2e 00 34 00 36 00 2e 00 31 00 38 00 2e 00 34 00 39 00 } //10 69.46.18.49
		$a_01_3 = {77 73 6b 57 65 62 53 65 72 76 65 72 4d 61 69 6e } //10 wskWebServerMain
		$a_01_4 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //1 capGetDriverDescriptionA
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=71
 
}