
rule TrojanSpy_Win32_Bancos_IS{
	meta:
		description = "TrojanSpy:Win32/Bancos.IS,SIGNATURE_TYPE_PEHSTR,40 00 40 00 0c 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d 23 30 30 30 31 23 47 4f 23 68 74 74 70 73 3a 2f 2f 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d } //10 http://mail.yahoo.com#0001#GO#https://mail.yahoo.com
		$a_01_1 = {62 61 72 63 6c 61 79 73 2e 63 6f 2e 75 6b 23 30 30 34 23 53 45 4e 44 23 4e 4f 23 } //10 barclays.co.uk#004#SEND#NO#
		$a_01_2 = {68 73 62 63 2e 63 6f 2e 75 6b 23 30 31 30 23 53 43 52 45 45 4e 23 4e 4f 23 } //10 hsbc.co.uk#010#SCREEN#NO#
		$a_01_3 = {6f 6c 62 32 2e 6e 61 74 69 6f 6e 65 74 2e 63 6f 6d 23 30 31 31 23 53 45 4e 44 23 4e 4f 23 } //10 olb2.nationet.com#011#SEND#NO#
		$a_01_4 = {64 65 75 74 73 63 68 65 2d 62 61 6e 6b 2e 64 65 23 30 31 32 23 54 41 4e 23 6d 43 6b 23 } //10 deutsche-bank.de#012#TAN#mCk#
		$a_01_5 = {6e 77 6f 6c 62 2e 63 6f 6d 23 30 31 33 23 53 45 4e 44 23 4e 4f 23 } //10 nwolb.com#013#SEND#NO#
		$a_01_6 = {6f 6e 6c 69 6e 65 2e 70 68 70 } //1 online.php
		$a_01_7 = {72 65 70 6f 72 74 65 72 2e 70 68 70 } //1 reporter.php
		$a_01_8 = {6e 61 76 69 67 61 74 6f 72 2e 70 68 70 } //1 navigator.php
		$a_01_9 = {67 6f 6c 64 } //1 gold
		$a_01_10 = {63 61 73 68 } //1 cash
		$a_01_11 = {62 61 6e 6b } //1 bank
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=64
 
}