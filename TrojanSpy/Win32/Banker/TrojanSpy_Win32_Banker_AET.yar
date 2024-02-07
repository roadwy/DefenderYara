
rule TrojanSpy_Win32_Banker_AET{
	meta:
		description = "TrojanSpy:Win32/Banker.AET,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 db 7c 65 8b 45 90 01 01 c1 e0 90 01 01 03 d8 89 5d 90 01 01 83 c7 90 01 01 83 ff 08 7c 48 83 ef 08 8b cf 90 00 } //01 00 
		$a_00_1 = {41 76 69 73 6f 20 49 6d 70 6f 72 74 61 6e 74 65 } //01 00  Aviso Importante
		$a_00_2 = {43 72 68 6f 6d 65 2e 65 78 65 } //01 00  Crhome.exe
		$a_00_3 = {66 65 6e 69 78 5c 54 41 4d 5c 7a 73 61 6e 74 61 6f } //00 00  fenix\TAM\zsantao
	condition:
		any of ($a_*)
 
}