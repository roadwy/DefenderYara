
rule TrojanSpy_Win32_Bancos_AJB{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {31 43 6c 69 63 6b 13 00 ?? ?? ?? ?? ?? 49 6d 61 67 65 90 0f 02 00 43 6c 69 63 6b } //10
		$a_00_1 = {49 00 6e 00 69 00 63 00 69 00 61 00 72 00 20 00 41 00 74 00 75 00 61 00 6c 00 69 00 7a 00 61 00 e7 00 e3 00 6f 00 2e 00 00 00 } //10
		$a_00_2 = {41 00 73 00 73 00 69 00 6e 00 61 00 74 00 75 00 72 00 61 00 20 00 45 00 6c 00 65 00 74 00 72 00 f4 00 6e 00 69 00 63 00 61 00 20 00 49 00 6e 00 76 00 e1 00 6c 00 69 00 64 00 61 00 2e 00 00 00 } //10
		$a_00_3 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 61 00 5c 00 74 00 6b 00 2e 00 74 00 78 00 74 00 00 00 } //1
		$a_00_4 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 61 00 5c 00 74 00 6d 00 2e 00 74 00 78 00 74 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}