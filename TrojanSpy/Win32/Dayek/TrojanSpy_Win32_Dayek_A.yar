
rule TrojanSpy_Win32_Dayek_A{
	meta:
		description = "TrojanSpy:Win32/Dayek.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e2 01 83 fa 01 75 15 c7 45 fc 06 00 00 00 ba 90 01 04 8d 4d 90 01 01 ff 15 90 00 } //01 00 
		$a_01_1 = {61 00 64 00 6b 00 65 00 79 00 2e 00 70 00 68 00 70 00 } //02 00  adkey.php
		$a_01_2 = {4d 61 69 6e 45 78 00 00 47 65 74 4c 6f 67 73 00 50 72 6f 4d 61 6e 00 00 48 54 54 50 43 6c 61 73 73 00 00 00 52 65 64 4d 6f 64 00 } //02 00 
		$a_01_3 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 45 00 78 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 45 00 78 00 2e 00 76 00 62 00 70 00 } //00 00  \UpdateEx\UpdateEx.vbp
	condition:
		any of ($a_*)
 
}