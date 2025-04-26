
rule TrojanDownloader_BAT_Small_CDS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.CDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0d 00 00 "
		
	strings :
		$a_80_0 = {44 65 6c 65 74 65 46 69 6c 65 57 } //DeleteFileW  3
		$a_80_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //GetExecutingAssembly  3
		$a_80_2 = {49 6e 65 74 43 68 65 63 6b } //InetCheck  3
		$a_80_3 = {40 65 63 68 6f 20 6f 66 66 } //@echo off  3
		$a_80_4 = {53 65 6c 66 44 65 6c 65 74 65 } //SelfDelete  3
		$a_80_5 = {56 61 6c 69 64 61 74 65 52 65 6d 6f 74 65 43 65 72 74 69 66 69 63 61 74 65 } //ValidateRemoteCertificate  3
		$a_00_6 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 30 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //3 /C choice /C Y /N /D Y /T 0 & Del
		$a_80_7 = {77 69 72 65 73 68 61 72 6b 20 70 6f 72 74 61 62 6c 65 } //wireshark portable  2
		$a_80_8 = {73 79 73 69 6e 74 65 72 6e 61 6c 73 20 74 63 70 76 69 65 77 } //sysinternals tcpview  2
		$a_80_9 = {61 6e 76 69 72 } //anvir  2
		$a_80_10 = {50 72 6f 63 65 73 73 20 45 78 70 6c 6f 72 65 72 } //Process Explorer  2
		$a_80_11 = {54 61 73 6b 4d 61 6e 61 67 65 72 } //TaskManager  2
		$a_80_12 = {68 74 74 70 20 61 6e 61 6c 79 7a 65 72 20 73 74 61 6e 64 2d 61 6c 6f 6e 65 } //http analyzer stand-alone  2
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_00_6  & 1)*3+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2) >=33
 
}