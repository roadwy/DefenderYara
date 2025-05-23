
rule TrojanSpy_Win32_Banker_ANX{
	meta:
		description = "TrojanSpy:Win32/Banker.ANX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 10 00 00 "
		
	strings :
		$a_01_0 = {43 00 61 00 72 00 74 00 61 00 6f 00 20 00 64 00 65 00 20 00 43 00 72 00 65 00 64 00 69 00 74 00 6f 00 20 00 3a 00 } //1 Cartao de Credito :
		$a_01_1 = {43 00 6f 00 64 00 2e 00 20 00 64 00 65 00 20 00 53 00 65 00 67 00 2e 00 20 00 20 00 43 00 61 00 72 00 64 00 3a 00 } //1 Cod. de Seg.  Card:
		$a_01_2 = {53 00 65 00 6e 00 68 00 61 00 20 00 64 00 65 00 20 00 53 00 65 00 69 00 73 00 3a 00 } //1 Senha de Seis:
		$a_01_3 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 3a 00 20 00 55 00 6d 00 20 00 6f 00 75 00 20 00 6d 00 61 00 69 00 73 00 20 00 64 00 61 00 64 00 6f 00 73 00 20 00 65 00 73 00 74 00 } //1 Informa: Um ou mais dados est
		$a_01_4 = {42 00 52 00 41 00 44 00 41 00 20 00 43 00 41 00 53 00 48 00 45 00 52 00 3a 00 } //1 BRADA CASHER:
		$a_00_5 = {53 00 45 00 4e 00 48 00 41 00 20 00 43 00 41 00 52 00 54 00 41 00 4f 00 3a 00 } //1 SENHA CARTAO:
		$a_01_6 = {50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 20 00 49 00 54 00 41 00 20 00 3a 00 } //1 PASSWORD ITA :
		$a_01_7 = {53 00 41 00 4e 00 54 00 41 00 4e 00 44 00 45 00 52 00 20 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 21 00 3a 00 } //1 SANTANDER INFORMA!:
		$a_01_8 = {43 00 56 00 56 00 2e 00 3a 00 } //1 CVV.:
		$a_01_9 = {43 00 50 00 46 00 2e 00 3a 00 } //1 CPF.:
		$a_01_10 = {53 00 79 00 73 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 74 00 78 00 74 00 } //1 SysLoader\install.txt
		$a_01_11 = {69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 63 00 61 00 69 00 78 00 61 00 } //1 internetbankingcaixa
		$a_01_12 = {42 00 42 00 20 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 20 00 3a 00 20 00 44 00 69 00 67 00 69 00 74 00 65 00 } //1 BB INFORMA : Digite
		$a_01_13 = {48 00 73 00 62 00 63 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 3a 00 20 00 44 00 69 00 67 00 69 00 74 00 65 00 } //1 Hsbc Informa: Digite
		$a_01_14 = {54 00 73 00 6b 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //1 TskManager
		$a_01_15 = {73 00 65 00 6e 00 64 00 65 00 72 00 65 00 64 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 74 00 6d 00 70 00 } //1 senderedemail.tmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=8
 
}
rule TrojanSpy_Win32_Banker_ANX_2{
	meta:
		description = "TrojanSpy:Win32/Banker.ANX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0d 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 3a 00 20 00 55 00 6d 00 20 00 6f 00 75 00 20 00 6d 00 61 00 69 00 73 00 20 00 64 00 61 00 64 00 6f 00 73 00 20 00 65 00 73 00 74 00 } //1 Informa: Um ou mais dados est
		$a_03_1 = {43 00 56 00 56 00 [0-01] 3a 00 } //1
		$a_03_2 = {43 00 50 00 46 00 [0-01] 3a 00 } //1
		$a_01_3 = {44 00 41 00 54 00 41 00 20 00 4e 00 41 00 53 00 43 00 2e 00 } //1 DATA NASC.
		$a_01_4 = {5c 00 49 00 4e 00 46 00 2e 00 74 00 78 00 74 00 } //1 \INF.txt
		$a_01_5 = {53 00 45 00 4e 00 48 00 41 00 5f 00 43 00 41 00 52 00 44 00 3a 00 } //1 SENHA_CARD:
		$a_01_6 = {6f 00 20 00 64 00 65 00 20 00 72 00 65 00 63 00 61 00 64 00 61 00 73 00 74 00 72 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 20 00 72 00 65 00 61 00 6c 00 69 00 7a 00 61 00 64 00 61 00 20 00 63 00 6f 00 6d 00 20 00 73 00 75 00 63 00 65 00 73 00 73 00 6f 00 21 00 2e 00 } //1 o de recadastramento realizada com sucesso!.
		$a_01_7 = {53 00 65 00 6e 00 68 00 61 00 20 00 42 00 61 00 6e 00 6b 00 20 00 46 00 6f 00 6e 00 65 00 20 00 42 00 42 00 20 00 69 00 6e 00 63 00 6f 00 72 00 72 00 65 00 74 00 61 00 21 00 } //1 Senha Bank Fone BB incorreta!
		$a_01_8 = {53 00 65 00 6e 00 68 00 61 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 42 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 3a 00 } //1 Senha Internet Banking:
		$a_01_9 = {53 00 75 00 61 00 20 00 73 00 65 00 6e 00 68 00 61 00 20 00 64 00 65 00 76 00 65 00 20 00 74 00 65 00 72 00 20 00 6d 00 61 00 69 00 73 00 20 00 64 00 65 00 20 00 36 00 20 00 63 00 61 00 72 00 61 00 63 00 74 00 65 00 72 00 65 00 73 00 } //1 Sua senha deve ter mais de 6 caracteres
		$a_01_10 = {6c 00 69 00 64 00 6f 00 73 00 2c 00 20 00 70 00 6f 00 72 00 20 00 66 00 61 00 76 00 6f 00 72 00 2c 00 20 00 74 00 65 00 6e 00 74 00 65 00 20 00 6e 00 6f 00 76 00 61 00 6d 00 65 00 6e 00 74 00 65 00 2e 00 } //1 lidos, por favor, tente novamente.
		$a_01_11 = {44 00 61 00 74 00 61 00 20 00 64 00 65 00 20 00 4e 00 61 00 73 00 63 00 69 00 6d 00 65 00 6e 00 74 00 6f 00 20 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 61 00 21 00 } //1 Data de Nascimento Invalida!
		$a_01_12 = {64 00 65 00 20 00 43 00 50 00 46 00 20 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 6f 00 21 00 } //1 de CPF Invalido!
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=8
 
}