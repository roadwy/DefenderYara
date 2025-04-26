
rule Trojan_Win32_Guloader_CE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0e 00 00 "
		
	strings :
		$a_01_0 = {50 75 6e 61 6c 75 61 6e 32 33 37 2e 6c 79 6e } //1 Punaluan237.lyn
		$a_01_1 = {6c 75 66 74 66 61 72 74 73 6c 6f 76 65 6e 65 2e 74 78 74 } //1 luftfartslovene.txt
		$a_01_2 = {73 75 62 70 6f 74 65 6e 63 69 65 73 2e 77 65 61 } //1 subpotencies.wea
		$a_01_3 = {4d 65 6e 73 74 72 75 65 72 65 6e 64 65 73 32 35 34 2e 6d 61 74 } //1 Menstruerendes254.mat
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 74 75 73 6b 65 } //1 Software\tuske
		$a_01_5 = {64 79 72 65 6b 72 6f 70 70 65 72 2e 68 79 70 } //1 dyrekropper.hyp
		$a_01_6 = {50 69 6e 6a 65 72 73 36 32 2e 73 61 6d } //1 Pinjers62.sam
		$a_01_7 = {6b 6f 6e 74 6f 72 61 75 74 6f 6d 61 74 69 73 65 72 69 6e 67 65 72 5c 61 6e 64 61 6d 61 6e 65 73 65 2e 64 6c 6c } //1 kontorautomatiseringer\andamanese.dll
		$a_01_8 = {4d 75 6c 74 69 70 6c 69 6b 61 74 69 6f 6e 65 72 73 2e 75 64 62 } //1 Multiplikationers.udb
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 69 6e 64 64 61 74 61 66 69 6c 65 6e 5c 73 6c 75 74 73 6b 65 6d 61 } //1 Software\inddatafilen\slutskema
		$a_01_10 = {74 79 6c 76 74 5c 53 68 6f 77 65 72 69 6e 65 73 73 2e 69 6e 69 } //1 tylvt\Showeriness.ini
		$a_01_11 = {65 6d 70 69 72 65 6b 6a 6f 6c 65 72 73 2e 74 78 74 } //1 empirekjolers.txt
		$a_01_12 = {74 61 70 65 69 6e 6f 63 65 70 68 61 6c 69 63 5c 4e 6f 6e 69 6d 69 74 61 74 69 76 65 } //1 tapeinocephalic\Nonimitative
		$a_01_13 = {75 6e 63 6f 6c 6f 72 65 64 25 5c 43 68 65 66 6b 6f 6b 6b 65 6e 73 31 39 31 5c 64 61 6e 6e 65 6b 76 69 6e 64 65 6e 73 2e 6f 66 66 } //1 uncolored%\Chefkokkens191\dannekvindens.off
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=7
 
}