
rule TrojanSpy_Win32_Bancos_OG{
	meta:
		description = "TrojanSpy:Win32/Bancos.OG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 } //3
		$a_03_1 = {4e 65 74 73 63 70 36 90 02 10 4f 70 65 72 61 90 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}