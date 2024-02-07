
rule Trojan_Win32_Datimorn_A{
	meta:
		description = "Trojan:Win32/Datimorn.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 54 41 52 54 20 20 2f 44 20 43 3a 20 2f 42 20 77 69 6e 33 32 2e 65 78 65 20 2d 75 20 68 74 74 70 3a 2f 2f } //01 00  START  /D C: /B win32.exe -u http://
		$a_03_1 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 22 43 3a 2f 4b 65 72 6e 65 6c 73 2f 64 72 69 76 65 72 2f 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2d 6f 20 68 74 74 70 3a 2f 2f 90 02 1f 2d 75 90 00 } //01 00 
		$a_00_2 = {43 3a 2f 4b 65 72 6e 65 6c 73 2f 64 72 69 76 65 72 73 2e 76 62 73 } //01 00  C:/Kernels/drivers.vbs
		$a_01_3 = {8d 9d 68 fe ff ff b0 00 ba 86 00 00 00 89 df 89 d1 f3 aa 8d 85 34 fe ff ff 89 44 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}