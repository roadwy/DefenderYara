
rule Backdoor_Win32_Poftsyun_A{
	meta:
		description = "Backdoor:Win32/Poftsyun.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6e 64 20 6e 6f 74 20 73 75 70 70 6f 72 74 21 } //1 nd not support!
		$a_01_1 = {6f 74 20 63 72 65 61 74 65 20 66 69 6c 65 20 6f 6e 20 63 6c 69 65 6e 74 21 } //1 ot create file on client!
		$a_01_2 = {53 65 72 76 65 72 66 69 6c 65 20 69 73 20 73 6d 61 6c 6c 65 72 20 74 68 61 6e 20 43 6c 69 65 6e 74 66 69 6c 65 21 } //1 Serverfile is smaller than Clientfile!
		$a_01_3 = {43 6c 69 65 6e 74 46 69 6c 65 20 69 73 20 73 6d 61 6c 6c 65 72 20 74 68 61 6e 20 53 65 72 76 65 72 46 69 6c 65 21 } //1 ClientFile is smaller than ServerFile!
		$a_01_4 = {6f 74 20 6f 70 65 6e 20 66 69 6c 65 20 6f 6e 20 63 6c 69 65 6e 74 20 77 69 74 68 20 61 70 70 65 6e 64 20 6d 6f 64 65 21 } //1 ot open file on client with append mode!
		$a_01_5 = {69 73 20 6e 6f 74 20 65 78 69 73 74 20 6f 72 20 73 74 6f 70 70 65 64 21 } //1 is not exist or stopped!
		$a_01_6 = {5f 5f 75 74 6d 7a 25 33 44 31 37 33 32 37 32 33 37 33 } //1 __utmz%3D173272373
		$a_01_7 = {74 72 61 6e 73 6c 61 74 65 5f 6c 6f 67 6f 2e 67 69 66 } //1 translate_logo.gif
		$a_01_8 = {50 72 6f 78 79 20 54 79 70 65 3a 25 73 } //1 Proxy Type:%s
		$a_01_9 = {2f 64 63 2f 6c 61 75 6e 63 68 } //1 /dc/launch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}