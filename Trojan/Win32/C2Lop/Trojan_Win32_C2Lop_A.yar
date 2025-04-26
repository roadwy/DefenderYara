
rule Trojan_Win32_C2Lop_A{
	meta:
		description = "Trojan:Win32/C2Lop.A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 2e 63 67 69 3f 73 } //10 http://%s/search/search.cgi?s
		$a_01_1 = {42 61 64 20 45 6c 6d 6f } //10 Bad Elmo
		$a_01_2 = {43 61 73 69 6e 6f 20 4f 6e 6c 69 6e 65 } //1 Casino Online
		$a_01_3 = {4f 6e 6c 69 6e 65 20 50 68 61 72 6d 61 63 79 } //1 Online Pharmacy
		$a_01_4 = {46 75 6e 20 53 74 75 66 66 } //1 Fun Stuff
		$a_01_5 = {43 6f 6f 6c 20 53 74 75 66 66 } //1 Cool Stuff
		$a_01_6 = {6d 70 33 73 65 72 63 68 2e 65 78 65 } //1 mp3serch.exe
		$a_01_7 = {6c 6f 70 73 65 61 72 63 68 2e 65 78 65 } //1 lopsearch.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}