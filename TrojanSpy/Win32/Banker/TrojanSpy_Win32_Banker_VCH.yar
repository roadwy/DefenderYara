
rule TrojanSpy_Win32_Banker_VCH{
	meta:
		description = "TrojanSpy:Win32/Banker.VCH,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 30 4e 54 34 3a } //1 C0NT4:
		$a_01_1 = {34 47 33 4e 43 31 41 3a } //1 4G3NC1A:
		$a_01_2 = {34 53 53 31 4e 34 54 55 52 34 3a } //1 4SS1N4TUR4:
		$a_01_3 = {62 61 6e 6b 69 6e 67 2e 63 61 69 78 61 2e 67 6f 76 2e 62 72 2f 53 49 49 42 43 2f 69 6e 64 65 78 2e 70 72 6f 63 65 73 73 61 } //1 banking.caixa.gov.br/SIIBC/index.processa
		$a_01_4 = {43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 CURRENTVERSION\RUN
		$a_01_5 = {53 65 6e 68 61 20 69 6e 63 6f 72 72 65 74 61 2e } //1 Senha incorreta.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}