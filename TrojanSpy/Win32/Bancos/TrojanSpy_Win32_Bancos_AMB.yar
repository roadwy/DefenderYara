
rule TrojanSpy_Win32_Bancos_AMB{
	meta:
		description = "TrojanSpy:Win32/Bancos.AMB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 6d 70 6f 00 00 00 56 61 6c 6f 72 00 00 00 44 61 64 6f 73 00 00 00 43 6f 64 69 67 6f 53 54 52 00 } //1
		$a_01_1 = {55 73 65 72 4e 61 6d 65 00 00 00 00 50 61 73 73 77 6f 72 64 00 00 00 00 } //1
		$a_00_2 = {5a 00 3a 00 5c 00 61 00 5f 00 6e 00 65 00 77 00 5f 00 64 00 6c 00 6c 00 5c 00 56 00 49 00 56 00 41 00 58 00 2e 00 76 00 62 00 70 00 } //1 Z:\a_new_dll\VIVAX.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}