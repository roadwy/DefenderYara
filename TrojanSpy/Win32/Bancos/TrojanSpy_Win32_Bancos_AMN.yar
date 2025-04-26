
rule TrojanSpy_Win32_Bancos_AMN{
	meta:
		description = "TrojanSpy:Win32/Bancos.AMN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 62 6d 67 63 6f 6e 73 69 67 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 www.bmgconsig.com.br|LOGIN'+login+'|SENHA:'+senha
		$a_01_1 = {77 77 77 2e 69 62 63 6f 6e 73 69 67 77 65 62 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 } //1 www.ibconsigweb.com.br|LOGIN:'+login+'|SENHA:'+s
		$a_01_2 = {6c 6f 67 69 6e 2e 62 61 6e 63 6f 62 6f 6e 73 75 63 65 73 73 6f 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 login.bancobonsucesso.com.br|LOGIN:'+login+'|SENHA:'+senha
		$a_01_3 = {61 75 74 6f 72 69 7a 61 64 6f 72 2e 62 67 6e 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 autorizador.bgn.com.br|LOGIN:'+login+'|SENHA:'+senha
		$a_01_4 = {62 6f 6e 70 61 72 63 65 69 72 6f 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 bonparceiro.com.br|LOGIN:'+login+'|SENHA:'+senha
		$a_01_5 = {72 65 70 72 65 73 65 6e 74 61 6e 74 65 6f 6e 6c 69 6e 65 2e 73 61 62 65 6d 69 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 representanteonline.sabemi.com.br|LOGIN:'+login+'|SENHA:'+senha
		$a_01_6 = {77 77 77 2e 70 61 6e 63 72 65 64 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 www.pancred.com.br|LOGIN:'+login+'|SENHA:'+senha
		$a_01_7 = {6c 6f 67 69 6e 2e 6c 69 76 65 2e 63 6f 6d 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 login.live.com|LOGIN:'+login+'|SENHA:'+senha
		$a_01_8 = {63 6f 6e 73 69 67 6e 61 64 6f 2e 64 61 79 63 6f 76 61 6c 2e 63 6f 6d 2e 62 72 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 consignado.daycoval.com.br|LOGIN:'+login+'|SENHA:'+senha
		$a_01_9 = {64 65 78 74 2e 64 65 73 70 65 67 61 72 2e 63 6f 6d 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 dext.despegar.com|LOGIN:'+login+'|SENHA:'+senha
		$a_01_10 = {77 77 77 2e 73 6f 66 69 73 61 64 69 72 65 74 6f 2e 63 6f 6d 2e 62 72 2f 41 63 63 6f 75 6e 74 2f 4c 6f 67 4f 6e 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e 2b 27 7c 53 45 4e 48 41 3a 27 2b 73 65 6e 68 61 } //1 www.sofisadireto.com.br/Account/LogOn|LOGIN:'+login+'|SENHA:'+senha
		$a_01_11 = {54 49 50 4f 3a 3c 42 41 49 58 41 20 44 45 20 47 52 41 56 41 4d 45 3e 7c 4c 4f 47 49 4e 3a 27 2b 6c 6f 67 69 6e } //1 TIPO:<BAIXA DE GRAVAME>|LOGIN:'+login
		$a_01_12 = {43 43 50 41 47 53 45 47 55 52 4f 3a 27 2b 6e 75 6d 65 72 6f 43 61 72 74 61 6f 2b 27 7c 27 2b 6d 65 73 2b 27 7c 27 2b 61 6e 6f 2b 27 7c 27 2b 63 6f 64 53 65 67 75 72 61 6e 63 61 } //1 CCPAGSEGURO:'+numeroCartao+'|'+mes+'|'+ano+'|'+codSeguranca
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=10
 
}