
rule TrojanSpy_Win32_Bancos_RH{
	meta:
		description = "TrojanSpy:Win32/Bancos.RH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 68 61 6e 68 61 69 69 63 68 69 62 61 2e 63 6f 6d 2f 62 61 6e 6e 65 72 5f 69 6e 63 2e 70 68 70 } //01 00  http://www.shanhaiichiba.com/banner_inc.php
		$a_01_1 = {61 20 2d 20 42 72 61 64 65 73 63 6f 20 49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 } //01 00  a - Bradesco Internet Banking
		$a_01_2 = {53 45 4e 48 41 20 36 3a 25 73 } //00 00  SENHA 6:%s
	condition:
		any of ($a_*)
 
}