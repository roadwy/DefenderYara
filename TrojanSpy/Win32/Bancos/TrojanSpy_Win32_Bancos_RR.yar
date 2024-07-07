
rule TrojanSpy_Win32_Bancos_RR{
	meta:
		description = "TrojanSpy:Win32/Bancos.RR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {42 4b 62 68 54 62 7e 58 42 4b 21 3b ba 28 c3 } //2
		$a_01_1 = {0f b7 1a 0f bf 31 0f af de 81 c3 00 08 00 00 8b 74 24 24 c1 fb 0c 83 c1 02 89 1e 83 c2 02 83 44 24 24 04 40 83 f8 40 7c d7 } //2
		$a_00_2 = {43 3a 20 73 65 72 69 61 6c 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a } //1 C: serial..........:
		$a_00_3 = {63 72 65 64 65 6e 74 69 61 6c 73 2e 41 43 43 45 53 53 5f 43 4f 44 45 } //1 credentials.ACCESS_CODE
		$a_00_4 = {2f 43 61 69 78 61 25 32 30 44 69 72 65 63 74 61 25 32 30 4f 6e 6c 69 6e 65 2f } //1 /Caixa%20Directa%20Online/
		$a_01_5 = {61 74 74 72 69 62 20 2d 68 20 22 63 3a } //1 attrib -h "c:
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}