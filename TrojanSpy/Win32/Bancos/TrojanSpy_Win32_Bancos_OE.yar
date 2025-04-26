
rule TrojanSpy_Win32_Bancos_OE{
	meta:
		description = "TrojanSpy:Win32/Bancos.OE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 3a 70 74 74 68 00 } //1 ⼯瀺瑴h
		$a_01_1 = {53 65 6e 68 61 } //1 Senha
		$a_01_2 = {2a 7c 7c 2a 20 49 6e 66 65 63 74 65 64 00 } //1 簪⩼䤠普捥整d
		$a_01_3 = {6d 6f 63 2e 6c 69 61 6d 67 40 } //1 moc.liamg@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}