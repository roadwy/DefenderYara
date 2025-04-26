
rule TrojanSpy_Win32_Bancos_RN{
	meta:
		description = "TrojanSpy:Win32/Bancos.RN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 00 31 00 54 00 31 00 42 00 4e 00 4b 00 00 00 } //1
		$a_00_1 = {4e 00 52 00 5f 00 43 00 41 00 52 00 54 00 41 00 4f 00 } //1 NR_CARTAO
		$a_01_2 = {54 58 54 5f 53 45 4e 48 41 00 } //1 塔彔䕓䡎A
		$a_01_3 = {42 41 52 44 45 4d 41 45 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}