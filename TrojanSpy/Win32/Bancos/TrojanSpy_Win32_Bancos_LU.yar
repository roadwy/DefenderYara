
rule TrojanSpy_Win32_Bancos_LU{
	meta:
		description = "TrojanSpy:Win32/Bancos.LU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6f 6b 63 68 69 73 74 6f 72 79 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 73 6d 69 6c 69 65 73 2f 65 6e 2d 47 42 31 2e 70 68 70 } //01 00  http://www.okchistory.com/images/smilies/en-GB1.php
		$a_01_1 = {42 72 61 64 65 73 63 6f 20 2d 20 43 6f 6d 70 6f 6e 65 6e 74 65 20 64 65 20 53 65 67 75 72 61 6e e7 61 20 28 50 6c 75 67 20 49 6e 29 } //01 00 
		$a_01_2 = {0f b7 1a 0f bf 31 0f af de 81 c3 00 08 00 00 8b 74 24 24 c1 fb 0c 83 c1 02 89 1e 83 c2 02 83 44 24 24 04 40 83 f8 40 7c d7 } //00 00 
	condition:
		any of ($a_*)
 
}