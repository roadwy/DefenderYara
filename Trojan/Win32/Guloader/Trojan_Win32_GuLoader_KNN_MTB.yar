
rule Trojan_Win32_GuLoader_KNN_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.KNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 65 6c 76 62 65 73 74 65 6d 6d 65 6c 73 65 6e 73 20 53 65 74 75 70 } //1 Selvbestemmelsens Setup
		$a_81_1 = {64 65 63 6f 64 65 73 5c 49 6e 73 65 63 75 72 65 6c 79 2e 65 78 65 } //1 decodes\Insecurely.exe
		$a_81_2 = {5c 53 6b 69 64 65 62 61 6c 6c 65 72 6e 65 73 5c 62 6c 6f 6b 72 65 67 69 73 74 72 65 72 69 6e 67 65 72 6e 65 73 2e 67 69 66 } //1 \Skideballernes\blokregistreringernes.gif
		$a_81_3 = {45 6c 65 6b 74 72 6f 64 65 72 2e 6a 70 67 } //1 Elektroder.jpg
		$a_81_4 = {50 69 67 65 6f 6e 68 6f 6c 65 64 2e 4c 61 72 } //1 Pigeonholed.Lar
		$a_81_5 = {69 6e 64 6c 65 6a 72 69 6e 67 73 2e 62 61 74 } //1 indlejrings.bat
		$a_81_6 = {5c 61 75 74 65 6e 74 69 66 69 6b 61 74 69 6f 6e 65 72 6e 65 5c 73 68 65 70 68 65 72 64 6c 79 2e 69 6e 69 } //1 \autentifikationerne\shepherdly.ini
		$a_81_7 = {63 75 6d 69 64 69 6e 2e 69 6e 69 } //1 cumidin.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=6
 
}