
rule Trojan_BAT_Perseus_MA_MTB{
	meta:
		description = "Trojan:BAT/Perseus.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 68 00 77 00 69 00 64 00 33 00 31 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 https://hwid31.000webhostapp.com
		$a_01_1 = {49 73 4b 65 79 44 6f 77 6e } //1 IsKeyDown
		$a_01_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_01_3 = {4b 65 79 50 72 65 73 73 } //1 KeyPress
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_5 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_01_6 = {49 00 44 00 41 00 50 00 72 00 6f 00 } //1 IDAPro
		$a_01_7 = {4b 69 6c 6c } //1 Kill
		$a_01_8 = {49 00 44 00 41 00 44 00 65 00 6d 00 6f 00 } //1 IDADemo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}