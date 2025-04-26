
rule TrojanSpy_Win32_Bancos_AAM{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAM,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 00 62 00 32 00 6b 00 31 00 2e 00 64 00 6c 00 6c 00 2f 00 4c 00 4f 00 47 00 49 00 4e 00 } //10 ib2k1.dll/LOGIN
		$a_00_1 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //1
		$a_00_2 = {2e 63 6f 6d 2e 62 72 } //1 .com.br
		$a_03_3 = {63 6f 6e 66 69 72 6d 61 [0-10] 63 6c 69 63 6b } //1
		$a_00_4 = {73 65 6e 68 61 63 61 72 74 61 6f } //1 senhacartao
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=13
 
}