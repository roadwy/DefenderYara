
rule TrojanSpy_Win32_Bancos_QV{
	meta:
		description = "TrojanSpy:Win32/Bancos.QV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 15 8d 4d d8 50 51 ff d6 8b 15 ?? ?? ?? ?? 50 52 e8 } //1
		$a_00_1 = {61 00 74 00 61 00 64 00 70 00 70 00 61 00 00 00 } //1
		$a_00_2 = {74 00 61 00 64 00 2e 00 6c 00 69 00 73 00 74 00 61 00 73 00 00 00 } //1
		$a_00_3 = {45 00 4c 00 49 00 46 00 4f 00 52 00 50 00 52 00 45 00 53 00 55 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}