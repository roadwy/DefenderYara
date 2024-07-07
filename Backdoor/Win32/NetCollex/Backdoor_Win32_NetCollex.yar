
rule Backdoor_Win32_NetCollex{
	meta:
		description = "Backdoor:Win32/NetCollex,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 69 61 6c 65 72 73 2e 6e 65 74 63 6f 6c 6c 65 78 2e 6e 65 74 2f } //4 http://dialers.netcollex.net/
		$a_01_1 = {50 6c 65 61 73 65 20 77 61 69 74 2e 2e 20 69 6e 73 74 61 6c 6c 69 6e 67 3a 20 30 30 25 } //2 Please wait.. installing: 00%
		$a_01_2 = {52 45 46 49 44 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 } //2 REFID                          
		$a_01_3 = {44 69 61 6c 6c 65 72 } //2 Dialler
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Backdoor_Win32_NetCollex_2{
	meta:
		description = "Backdoor:Win32/NetCollex,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 65 78 69 74 20 48 54 54 50 2f 31 2e 30 } //1 GET /exit HTTP/1.0
		$a_01_1 = {57 61 6e 61 64 6f 6f } //1 Wanadoo
		$a_01_2 = {54 2d 4f 6e 6c 69 6e 65 20 53 74 61 72 74 43 65 6e 74 65 72 } //1 T-Online StartCenter
		$a_01_3 = {41 4f 4c 20 46 72 61 6d 65 32 35 } //1 AOL Frame25
		$a_01_4 = {4e 65 74 63 6f 6c 6c 65 78 20 4c 74 64 2c } //5 Netcollex Ltd,
		$a_01_5 = {6e 65 74 64 69 61 6c 65 72 73 } //1 netdialers
		$a_01_6 = {53 6f 72 72 79 2c 20 79 6f 75 72 20 74 69 6d 65 20 6c 69 6d 69 74 20 68 61 73 20 62 65 65 6e 20 65 78 63 65 65 64 65 64 20 66 6f 72 20 74 68 69 73 20 63 61 6c 6c } //3 Sorry, your time limit has been exceeded for this call
		$a_01_7 = {59 6f 75 20 63 61 6e 20 61 63 63 65 73 73 20 74 68 69 73 20 73 69 74 65 20 75 73 69 6e 67 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 64 65 74 61 69 6c 73 3a } //3 You can access this site using the following details:
		$a_01_8 = {63 63 61 72 64 2e 69 70 62 69 6c 6c 2e 63 6f 6d } //1 ccard.ipbill.com
		$a_01_9 = {4e 65 77 20 65 6e 74 72 79 3a 20 64 69 61 6c 20 25 73 20 64 65 76 69 63 65 20 25 73 20 74 79 70 65 20 25 73 } //2 New entry: dial %s device %s type %s
		$a_01_10 = {48 61 6e 67 75 70 41 6c 6c 3a 20 66 6e 52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 3d 25 64 } //2 HangupAll: fnRasEnumConnections=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=12
 
}