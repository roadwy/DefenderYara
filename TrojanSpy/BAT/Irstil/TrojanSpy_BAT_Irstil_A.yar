
rule TrojanSpy_BAT_Irstil_A{
	meta:
		description = "TrojanSpy:BAT/Irstil.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 37 2e 30 2e 30 2e 31 20 7a 65 6e 61 76 6f 74 61 74 61 2e 69 6e } //01 00  127.0.0.1 zenavotata.in
		$a_01_1 = {31 32 37 2e 30 2e 30 2e 31 20 65 77 6f 72 6c 64 2e 77 65 62 73 70 69 64 65 72 61 73 69 61 2e 63 6f 2e 69 6e } //01 00  127.0.0.1 eworld.webspiderasia.co.in
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 69 63 6f 6e 77 6f 72 6c 64 2e 61 73 69 61 } //01 00  127.0.0.1 iconworld.asia
		$a_01_3 = {31 32 37 2e 30 2e 30 2e 31 20 6e 67 65 6e 32 30 31 34 2e 61 73 69 61 } //01 00  127.0.0.1 ngen2014.asia
		$a_01_4 = {31 32 37 2e 30 2e 30 2e 31 20 7a 65 6e 65 76 6f 74 61 74 61 2e 69 6e } //01 00  127.0.0.1 zenevotata.in
		$a_01_5 = {31 32 37 2e 30 2e 30 2e 31 20 73 70 69 64 65 72 68 69 73 70 69 64 65 72 2e 69 6e } //01 00  127.0.0.1 spiderhispider.in
		$a_01_6 = {31 32 37 2e 30 2e 30 2e 31 20 62 6c 61 63 6b 74 73 77 69 74 68 66 6f 72 72 65 73 74 2e 63 6f 6d } //01 00  127.0.0.1 blacktswithforrest.com
		$a_01_7 = {31 32 37 2e 30 2e 30 2e 31 20 6d 79 74 69 63 6b 65 74 77 6f 72 6c 64 32 30 31 35 2e 63 6f 6d } //02 00  127.0.0.1 myticketworld2015.com
		$a_01_8 = {68 74 74 70 3a 2f 2f 37 30 2e 33 38 2e 34 30 2e 31 38 35 } //02 00  http://70.38.40.185
		$a_01_9 = {69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 } //02 00  ipconfig /flushdns
		$a_01_10 = {48 69 64 65 20 4d 79 20 41 73 73 20 50 72 6f 78 79 20 4c 69 73 74 } //01 00  Hide My Ass Proxy List
		$a_01_11 = {53 74 61 74 65 20 42 61 6e 6b 20 6f 66 20 49 6e 64 69 61 } //01 00  State Bank of India
		$a_01_12 = {48 44 46 43 20 42 61 6e 6b } //00 00  HDFC Bank
		$a_00_13 = {87 10 00 00 91 fa } //51 ab 
	condition:
		any of ($a_*)
 
}