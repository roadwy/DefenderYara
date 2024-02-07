
rule TrojanSpy_Win32_Banker_AJK{
	meta:
		description = "TrojanSpy:Win32/Banker.AJK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 6c 00 65 00 72 00 74 00 28 00 22 00 69 00 54 00 6f 00 6b 00 65 00 6e 00 20 00 69 00 6e 00 76 00 } //01 00  alert("iToken inv
		$a_01_1 = {4d 53 47 23 4d 65 74 65 20 6f 20 42 6f 6c 65 74 6f 20 42 6f 63 61 20 64 65 20 42 75 72 72 6f } //01 00  MSG#Mete o Boleto Boca de Burro
		$a_01_2 = {62 61 6e 6b 6c 69 6e 65 2e 69 74 61 75 2e 63 6f 6d 2e 62 72 } //01 00  bankline.itau.com.br
		$a_00_3 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //01 00 
		$a_00_4 = {73 65 6e 68 61 63 61 72 74 61 6f } //00 00  senhacartao
	condition:
		any of ($a_*)
 
}