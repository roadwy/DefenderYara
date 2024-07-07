
rule TrojanSpy_Win32_Bancos_DB{
	meta:
		description = "TrojanSpy:Win32/Bancos.DB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //10 drivers\etc\hosts
		$a_00_1 = {77 77 77 2e 75 6e 69 7a 6f 6e 2e 6e 6f 2f 25 32 30 2e 2f 65 6d 61 69 6c } //10 www.unizon.no/%20./email
		$a_02_2 = {32 30 30 2e 31 31 2e 32 33 32 2e 36 33 90 02 04 62 72 61 64 65 73 63 6f 2e 63 6f 6d 2e 62 72 90 00 } //10
		$a_00_3 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_00_4 = {62 62 2e 63 6f 6d 2e 62 72 } //1 bb.com.br
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1) >=41
 
}