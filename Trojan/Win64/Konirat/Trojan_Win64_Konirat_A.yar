
rule Trojan_Win64_Konirat_A{
	meta:
		description = "Trojan:Win64/Konirat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 72 00 62 00 69 00 72 00 79 00 32 00 6a 00 73 00 71 00 33 00 34 00 35 00 34 00 2e 00 65 00 78 00 65 00 } //1 wirbiry2jsq3454.exe
		$a_01_1 = {77 00 65 00 65 00 77 00 79 00 65 00 73 00 71 00 73 00 66 00 34 00 2e 00 65 00 78 00 65 00 } //1 weewyesqsf4.exe
		$a_01_2 = {6d 00 61 00 69 00 6c 00 2e 00 61 00 70 00 6d 00 2e 00 63 00 6f 00 2e 00 6b 00 72 00 } //1 mail.apm.co.kr
		$a_01_3 = {2e 2f 70 64 73 2f 64 61 74 61 2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 ./pds/data/upload.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}