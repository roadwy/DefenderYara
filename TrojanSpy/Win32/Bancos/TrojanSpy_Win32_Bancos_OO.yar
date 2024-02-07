
rule TrojanSpy_Win32_Bancos_OO{
	meta:
		description = "TrojanSpy:Win32/Bancos.OO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 } //01 00 
		$a_01_1 = {44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c } //01 00  Dados de aplicativos\
		$a_01_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //01 00  netsh firewall add allowedprogram
		$a_01_3 = {41 52 51 55 49 56 4f 20 4f 4b } //01 00  ARQUIVO OK
		$a_01_4 = {4f 52 4b 55 54 00 } //02 00  剏啋T
		$a_01_5 = {06 00 00 00 6c 4d 76 33 7a 71 00 } //00 00 
	condition:
		any of ($a_*)
 
}