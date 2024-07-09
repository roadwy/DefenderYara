
rule TrojanSpy_Win32_Banker_AET{
	meta:
		description = "TrojanSpy:Win32/Banker.AET,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {85 db 7c 65 8b 45 ?? c1 e0 ?? 03 d8 89 5d ?? 83 c7 ?? 83 ff 08 7c 48 83 ef 08 8b cf } //1
		$a_00_1 = {41 76 69 73 6f 20 49 6d 70 6f 72 74 61 6e 74 65 } //1 Aviso Importante
		$a_00_2 = {43 72 68 6f 6d 65 2e 65 78 65 } //1 Crhome.exe
		$a_00_3 = {66 65 6e 69 78 5c 54 41 4d 5c 7a 73 61 6e 74 61 6f } //1 fenix\TAM\zsantao
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}