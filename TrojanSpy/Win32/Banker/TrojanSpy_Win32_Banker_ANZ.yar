
rule TrojanSpy_Win32_Banker_ANZ{
	meta:
		description = "TrojanSpy:Win32/Banker.ANZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 79 6d 61 6e 74 65 63 20 4e 65 74 44 72 69 76 65 72 20 4d 6f 6e 69 74 6f 72 00 } //1
		$a_01_1 = {4d 63 41 66 65 65 2e 49 6e 73 74 61 6e 74 55 70 64 61 74 65 2e 4d 6f 6e 69 74 6f 72 00 } //1
		$a_01_2 = {2e 67 6f 76 2e 62 72 2f } //1 .gov.br/
		$a_01_3 = {2a 2a 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 20 77 72 69 74 65 5f 61 64 64 72 3d 25 78 } //1 ** WriteProcessMemory failed write_addr=%x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}