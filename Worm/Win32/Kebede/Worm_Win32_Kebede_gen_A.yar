
rule Worm_Win32_Kebede_gen_A{
	meta:
		description = "Worm:Win32/Kebede.gen!A,SIGNATURE_TYPE_PEHSTR,18 00 17 00 0a 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 30 00 30 00 30 00 30 00 33 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 34 00 30 00 30 00 30 00 30 00 30 00 30 00 46 00 46 00 46 00 46 00 30 00 30 00 30 00 30 00 42 00 38 00 } //5 4D5A90000300000004000000FFFF0000B8
		$a_01_1 = {38 00 46 00 38 00 41 00 46 00 39 00 44 00 42 00 43 00 42 00 45 00 42 00 39 00 37 00 38 00 38 00 43 00 42 00 45 00 42 00 39 00 37 00 38 00 38 00 43 00 42 00 45 00 42 00 39 00 37 00 38 00 38 00 34 00 38 00 46 00 37 00 39 00 39 00 38 00 38 00 43 00 41 00 45 00 42 00 39 00 37 00 38 00 38 00 41 00 32 00 46 00 34 00 } //5 8F8AF9DBCBEB9788CBEB9788CBEB978848F79988CAEB9788A2F4
		$a_01_2 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //2 127.0.0.1
		$a_01_3 = {6c 73 74 57 61 62 46 69 6c 65 } //2 lstWabFile
		$a_01_4 = {6c 73 74 6d 61 69 6c } //2 lstmail
		$a_01_5 = {6c 73 74 6d 61 69 6c 65 72 } //2 lstmailer
		$a_01_6 = {4b 00 65 00 62 00 65 00 64 00 65 00 } //2 Kebede
		$a_01_7 = {4b 65 62 65 64 65 45 } //2 KebedeE
		$a_01_8 = {57 69 6e 64 6f 77 20 4c 61 79 65 72 64 20 53 65 72 76 69 63 65 20 50 72 6f 76 69 64 65 72 } //3 Window Layerd Service Provider
		$a_01_9 = {53 6f 63 6b 65 74 43 6f 6e 74 72 6f 6c } //2 SocketControl
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*3+(#a_01_9  & 1)*2) >=23
 
}