
rule TrojanSpy_Win32_Bancos_AJQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJQ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 69 74 65 50 61 72 61 45 6e 76 69 6f } //2 siteParaEnvio
		$a_01_1 = {50 49 44 6a 63 69 74 61 } //3 PIDjcita
		$a_01_2 = {74 72 61 76 61 5f 6d 6f 75 73 65 54 69 6d 65 72 } //3 trava_mouseTimer
		$a_01_3 = {6d 00 61 00 6e 00 64 00 61 00 2e 00 70 00 68 00 70 00 } //3 manda.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=11
 
}