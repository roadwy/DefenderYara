
rule Spammer_WinNT_Srizbi_A{
	meta:
		description = "Spammer:WinNT/Srizbi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d6 84 c0 74 1f 8d 7b 38 57 ff d6 84 c0 74 15 81 3f ef be ad de 75 0d 68 } //1
		$a_01_1 = {7c ed 89 10 8d 50 08 89 16 2b f8 83 ef 14 c6 02 58 8b 10 41 89 70 04 c6 40 09 68 89 50 0a c6 40 0e 50 c6 40 0f e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}