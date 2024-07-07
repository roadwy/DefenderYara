
rule TrojanSpy_Win32_Bancos_UW{
	meta:
		description = "TrojanSpy:Win32/Bancos.UW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 78 44 61 74 61 2e 64 6c 6c 00 49 41 53 46 48 42 49 41 53 53 56 4e 41 54 53 53 00 } //10 硆慄慴搮汬䤀十䡆䥂十噓䅎協S
		$a_01_1 = {54 59 58 4f 4d 41 53 4b 51 57 42 46 48 59 55 57 45 49 47 48 4e 02 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=10
 
}
rule TrojanSpy_Win32_Bancos_UW_2{
	meta:
		description = "TrojanSpy:Win32/Bancos.UW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 4a 41 53 48 42 46 48 4a 5a 53 56 43 48 53 48 55 49 45 57 54 00 } //1 䩔十䉈䡆婊噓䡃䡓䥕坅T
		$a_01_1 = {45 48 41 53 55 49 46 42 41 53 48 4a 42 45 52 55 49 54 45 48 52 54 4a 45 00 } //1
		$a_00_2 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}