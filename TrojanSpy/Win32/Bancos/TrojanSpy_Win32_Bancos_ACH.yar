
rule TrojanSpy_Win32_Bancos_ACH{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACH,SIGNATURE_TYPE_PEHSTR_EXT,70 00 6f 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 20 28 45 78 3a 20 54 6f 6b 65 6e 2c 20 43 44 2d 52 6f 6d 2c 20 64 69 73 71 75 65 74 65 20 } //100 Arquivo (Ex: Token, CD-Rom, disquete 
		$a_01_1 = {42 72 61 64 65 73 63 6f } //10 Bradesco
		$a_00_2 = {52 41 53 45 2c 20 44 42 5f 43 48 30 33 2c 20 44 42 5f 53 45 30 36 2c 20 4e 5f 4d 43 41 44 44 52 } //2 RASE, DB_CH03, DB_SE06, N_MCADDR
		$a_01_3 = {46 00 52 00 41 00 53 00 45 00 00 00 } //1
		$a_01_4 = {4d 00 43 00 41 00 44 00 44 00 52 00 45 00 53 00 53 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=111
 
}