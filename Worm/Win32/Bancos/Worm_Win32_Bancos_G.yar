
rule Worm_Win32_Bancos_G{
	meta:
		description = "Worm:Win32/Bancos.G,SIGNATURE_TYPE_PEHSTR_EXT,56 00 52 00 0c 00 00 "
		
	strings :
		$a_01_0 = {45 4e 44 45 52 45 43 4f 53 } //10 ENDERECOS
		$a_01_1 = {53 49 5a 45 53 45 43 41 4f } //10 SIZESECAO
		$a_01_2 = {53 4d 54 50 48 4f 53 54 } //10 SMTPHOST
		$a_01_3 = {4c 4f 47 49 4e 53 4d 54 50 } //10 LOGINSMTP
		$a_01_4 = {53 45 4e 48 41 53 4d 54 50 } //10 SENHASMTP
		$a_01_5 = {50 4f 50 53 45 52 56 45 52 } //10 POPSERVER
		$a_01_6 = {45 4d 41 49 4c 46 52 4f 4d } //10 EMAILFROM
		$a_01_7 = {67 65 74 44 6f 6d 69 6e 69 6f 44 61 55 52 4c } //5 getDominioDaURL
		$a_01_8 = {64 6f 77 6e 43 6f 6e 66 69 67 } //5 downConfig
		$a_01_9 = {64 6f 77 6e 43 6f 6e 66 69 67 4d 53 47 } //5 downConfigMSG
		$a_01_10 = {63 6f 6e 66 2e 69 6e 69 } //1 conf.ini
		$a_01_11 = {63 6f 6e 66 67 41 75 74 68 65 6e 74 69 63 2e 69 6e 69 } //1 confgAuthentic.ini
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=82
 
}