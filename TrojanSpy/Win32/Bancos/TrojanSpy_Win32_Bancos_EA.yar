
rule TrojanSpy_Win32_Bancos_EA{
	meta:
		description = "TrojanSpy:Win32/Bancos.EA,SIGNATURE_TYPE_PEHSTR_EXT,ffffffb0 01 ffffffb0 01 0f 00 00 "
		
	strings :
		$a_00_0 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b 50 72 6f 63 } //100 KeyboardHookProc
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //100 URLDownloadToFileA
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_00_3 = {47 65 72 65 6e 63 69 61 64 6f 72 20 46 69 6e 61 6e 63 65 69 72 6f 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //100 Gerenciador Financeiro - Microsoft Internet Explorer
		$a_00_4 = {5c 57 69 6e 64 6f 77 73 5c 68 6f 73 74 73 2e 6c 6f 67 } //10 \Windows\hosts.log
		$a_00_5 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 61 72 74 61 6f 2e 65 78 65 } //10 \windows\system\cartao.exe
		$a_02_6 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 6b 65 79 6c 6f 67 [0-02] 2e 64 6c 6c } //10
		$a_00_7 = {76 69 64 61 6e 6f 76 61 30 33 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //1 vidanova03@isbt.com.br
		$a_00_8 = {73 6d 74 70 2e 69 73 62 74 2e 63 6f 6d 2e 62 72 } //1 smtp.isbt.com.br
		$a_00_9 = {61 61 70 66 2f 61 61 69 2f 6c 6f 67 69 6e 2e 70 62 6b } //1 aapf/aai/login.pbk
		$a_00_10 = {61 61 70 66 2f 61 61 69 2f 70 72 69 6e 63 69 70 61 6c } //1 aapf/aai/principal
		$a_00_11 = {42 61 6e 63 6f 42 72 61 73 69 6c 2f 6f 66 66 69 63 65 4e 45 2f 69 6e 64 65 78 2e 68 74 6d } //1 BancoBrasil/officeNE/index.htm
		$a_00_12 = {68 74 74 70 3a 2f 2f 61 63 69 64 62 75 72 6e 2e 76 31 30 2e 63 6f 6d 2e 62 72 2f 6b 65 79 6c 6f 67 66 2e 64 6c 6c } //1 http://acidburn.v10.com.br/keylogf.dll
		$a_00_13 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 73 64 64 65 73 69 67 6e 73 2e 63 6f 6d 2f 63 66 2f 73 65 75 63 61 72 74 65 69 72 6f 2f 63 61 72 74 61 6f 32 2e 65 78 65 } //1 http://www.csddesigns.com/cf/seucarteiro/cartao2.exe
		$a_00_14 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 73 64 64 65 73 69 67 6e 73 2e 63 6f 6d 2f 63 66 2f 73 65 75 63 61 72 74 65 69 72 6f 2f 6b 65 79 6c 6f 67 66 2e 64 6c 6c } //1 http://www.csddesigns.com/cf/seucarteiro/keylogf.dll
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_02_6  & 1)*10+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=432
 
}