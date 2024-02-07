
rule TrojanSpy_Win32_Banker_VI{
	meta:
		description = "TrojanSpy:Win32/Banker.VI,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 70 5f 61 63 63 6f 75 6e 74 5f 6e 6f } //01 00  ep_account_no
		$a_01_1 = {65 70 5f 70 61 73 73 77 6f 72 64 } //01 00  ep_password
		$a_01_2 = {5f 4b 47 5c 30 2e 62 6d 70 } //01 00  _KG\0.bmp
		$a_01_3 = {2f 43 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //01 00  /Count.asp?mac=
		$a_01_4 = {68 74 74 70 3a 2f 2f 31 31 30 2e 33 34 2e 32 33 32 2e 31 31 3a 31 33 31 34 } //01 00  http://110.34.232.11:1314
		$a_01_5 = {49 4e 49 64 69 72 65 63 74 62 61 6e 6b 55 49 36 30 2e 64 6c 6c } //00 00  INIdirectbankUI60.dll
		$a_01_6 = {00 80 10 } //00 00 
	condition:
		any of ($a_*)
 
}