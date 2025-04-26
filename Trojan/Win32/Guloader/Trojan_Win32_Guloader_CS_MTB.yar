
rule Trojan_Win32_Guloader_CS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 79 6e 63 72 79 70 74 69 63 2e 73 75 6d } //1 syncryptic.sum
		$a_01_1 = {6f 72 74 68 6f 70 73 79 63 68 69 61 74 72 69 63 2e 74 78 74 } //1 orthopsychiatric.txt
		$a_01_2 = {63 6f 75 72 62 65 5c 6d 79 74 6f 6c 6f 67 69 65 72 6e 65 73 2e 64 6c 6c } //1 courbe\mytologiernes.dll
		$a_01_3 = {53 6f 6e 61 72 65 6e 73 5c 73 70 61 74 68 6f 73 65 2e 69 6e 69 } //1 Sonarens\spathose.ini
		$a_01_4 = {70 72 69 6d 74 61 6c 6c 65 6e 65 2e 42 65 74 } //1 primtallene.Bet
		$a_01_5 = {41 66 6b 6f 67 6e 69 6e 67 65 72 32 33 33 2e 73 79 73 } //1 Afkogninger233.sys
		$a_01_6 = {4b 61 73 74 73 2e 62 61 63 } //1 Kasts.bac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}