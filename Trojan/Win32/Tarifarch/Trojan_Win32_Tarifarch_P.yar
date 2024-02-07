
rule Trojan_Win32_Tarifarch_P{
	meta:
		description = "Trojan:Win32/Tarifarch.P,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {e3 ac 6f ed b3 f7 b9 fb ec bd cf 5a 17 00 92 a7 2f 97 97 06 4b 01 90 ca 13 f0 83 3c 9c e9 11 91 } //01 00 
		$a_01_1 = {2e 00 6f 00 70 00 65 00 6e 00 70 00 61 00 72 00 74 00 2e 00 72 00 75 00 2f 00 6e 00 65 00 77 00 74 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 3f 00 70 00 3d 00 71 00 63 00 61 00 73 00 68 00 } //01 00  .openpart.ru/newtoolbar?p=qcash
		$a_01_2 = {2f 00 72 00 65 00 62 00 69 00 6c 00 6c 00 2f 00 72 00 75 00 6c 00 65 00 73 00 } //01 00  /rebill/rules
		$a_01_3 = {6f 6e 4b 65 79 50 72 56 61 6c 69 64 4e 75 6d 62 65 72 } //01 00  onKeyPrValidNumber
		$a_01_4 = {65 70 43 6f 64 65 4b 65 79 50 72 65 73 73 } //00 00  epCodeKeyPress
	condition:
		any of ($a_*)
 
}