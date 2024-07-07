
rule TrojanSpy_Win32_Bancos_AIM{
	meta:
		description = "TrojanSpy:Win32/Bancos.AIM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 20 75 74 69 6c 69 7a 65 20 73 65 75 20 69 54 6f 6b 65 6e } //1 o utilize seu iToken
		$a_01_1 = {69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 6c 00 67 00 6e 00 65 00 74 00 2f 00 69 00 74 00 61 00 75 00 66 00 2f 00 62 00 61 00 6e 00 6b 00 6c 00 69 00 6e 00 65 00 2e 00 68 00 74 00 6d 00 } //1 itau.com.br/lgnet/itauf/bankline.htm
		$a_01_2 = {61 00 6c 00 65 00 72 00 74 00 28 00 22 00 69 00 54 00 6f 00 6b 00 65 00 6e 00 20 00 69 00 6e 00 76 00 } //1 alert("iToken inv
		$a_01_3 = {4d 53 47 23 4d 65 74 65 20 6f 20 42 6f 6c 65 74 6f 20 42 6f 63 61 20 64 65 20 42 75 72 72 6f } //1 MSG#Mete o Boleto Boca de Burro
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}