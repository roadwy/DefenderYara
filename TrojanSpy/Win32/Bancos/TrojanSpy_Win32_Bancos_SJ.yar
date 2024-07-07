
rule TrojanSpy_Win32_Bancos_SJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.SJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2a 00 5c 00 41 00 47 00 3a 00 5c 00 41 00 4d 00 5c 00 46 00 6f 00 6e 00 74 00 65 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 *\AG:\AM\Fonte\Project1.vbp
		$a_01_1 = {5b 62 62 2e 63 6f 6d 2e 62 72 5d 20 2d 20 20 42 61 6e 63 6f 20 64 6f 20 42 72 61 73 69 6c 20 2d 20 20 57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 [bb.com.br] -  Banco do Brasil -  Windows Internet Explorer
		$a_01_2 = {53 00 45 00 4e 00 48 00 41 00 20 00 44 00 4f 00 20 00 43 00 41 00 52 00 54 00 } //1 SENHA DO CART
		$a_01_3 = {61 00 75 00 74 00 65 00 6e 00 74 00 69 00 63 00 33 00 32 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 autentic321@gmail.com
		$a_01_4 = {63 00 68 00 65 00 67 00 61 00 64 00 61 00 33 00 32 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 chegada321@gmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}