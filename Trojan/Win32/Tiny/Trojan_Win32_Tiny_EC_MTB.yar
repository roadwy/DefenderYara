
rule Trojan_Win32_Tiny_EC_MTB{
	meta:
		description = "Trojan:Win32/Tiny.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 38 35 2e 32 31 35 2e 31 31 33 2e 38 34 2f 70 65 69 6e 73 74 61 6c 6c 2e 70 68 70 } //01 00  185.215.113.84/peinstall.php
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //01 00  URLDownloadToFileW
		$a_01_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 57 } //01 00  CreateProcessW
		$a_01_3 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //01 00  GetStartupInfoA
		$a_01_4 = {74 00 77 00 69 00 7a 00 74 00 2e 00 72 00 75 00 2f 00 6e 00 65 00 77 00 74 00 70 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  twizt.ru/newtpp.exe
	condition:
		any of ($a_*)
 
}