
rule TrojanSpy_Win32_Bancos_AHR{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 00 } //3
		$a_01_1 = {2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 2f 46 } //3 /IM iexplore.exe /F
		$a_01_2 = {00 2b 20 50 43 4e 61 6d 65 20 2b 00 } //1
		$a_01_3 = {00 70 72 61 71 75 65 6d 3d } //1
		$a_01_4 = {4e 75 6d 65 72 6f 20 53 00 } //1
		$a_01_5 = {73 6d 74 70 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //1 smtps.uol.com.br
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}