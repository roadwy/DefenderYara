
rule Trojan_Win32_Bladab_HAZ_MTB{
	meta:
		description = "Trojan:Win32/Bladab.HAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 22 22 25 61 70 70 64 61 74 61 25 5c 73 79 73 74 65 6d 55 70 64 61 74 65 5c 70 61 72 74 6e 65 72 2e 76 62 73 22 22 22 20 2c 20 30 2c 20 54 72 75 65 } //01 00  objShell.Run """%appdata%\systemUpdate\partner.vbs""" , 0, True
		$a_01_1 = {6e 73 6c 6f 6f 6b 75 70 20 6d 79 69 70 2e 6f 70 65 6e 64 6e 73 2e 63 6f 6d 2e 20 72 65 73 6f 6c 76 65 72 31 2e 6f 70 65 6e 64 6e 73 2e 63 6f 6d } //01 00  nslookup myip.opendns.com. resolver1.opendns.com
		$a_01_2 = {35 31 2e 38 39 2e 32 33 37 2e 32 33 34 } //01 00  51.89.237.234
		$a_01_3 = {73 75 73 68 69 2f 70 61 67 65 73 2f 63 6f 6e 74 72 6f 6c 6c 65 72 73 2f 73 65 73 73 69 6f 6e 5f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 } //01 00  sushi/pages/controllers/session_controller.php
		$a_01_4 = {5c 70 64 66 52 65 61 64 65 72 5c 70 61 69 64 61 72 64 2e 76 62 73 20 20 5c 70 64 66 52 65 61 64 65 72 5c 70 61 69 64 61 72 64 2e 62 61 74 } //00 00  \pdfReader\paidard.vbs  \pdfReader\paidard.bat
	condition:
		any of ($a_*)
 
}