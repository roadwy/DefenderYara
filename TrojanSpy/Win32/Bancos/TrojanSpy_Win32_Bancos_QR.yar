
rule TrojanSpy_Win32_Bancos_QR{
	meta:
		description = "TrojanSpy:Win32/Bancos.QR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 77 77 77 2e 62 72 61 64 65 73 63 6f 2e 63 6f 6d 2e 62 72 00 90 0a 04 00 2e 90 0a 04 00 2e 90 0a 04 00 2e } //1
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 6d 79 64 6c 6c 2e 64 6c 6c 2c 53 68 6f 77 46 6f 72 6d 20 00 } //1
		$a_01_2 = {43 3a 5c 70 62 68 2e 74 78 74 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}