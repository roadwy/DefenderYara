
rule Trojan_Win32_Guloader_SI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {42 72 6e 64 69 6e 67 65 72 6e 65 2e 61 66 66 } //1 Brndingerne.aff
		$a_81_1 = {70 6f 73 74 61 6e 76 69 73 6e 69 6e 67 65 72 73 2e 66 69 62 } //1 postanvisningers.fib
		$a_81_2 = {73 75 62 6a 65 6b 74 73 70 72 64 69 6b 61 74 65 72 73 2e 74 65 73 } //1 subjektsprdikaters.tes
		$a_81_3 = {6b 6f 73 74 70 6c 61 6e 65 72 5c 55 6e 69 6e 73 74 61 6c 6c 5c 67 69 70 73 70 6c 61 64 65 72 73 } //1 kostplaner\Uninstall\gipspladers
		$a_81_4 = {50 75 6e 63 74 61 74 65 5c 67 6e 69 73 74 72 65 64 65 73 } //1 Punctate\gnistredes
		$a_81_5 = {63 75 72 69 6f 75 73 6e 65 73 73 20 66 6f 72 75 72 65 6e 69 6e 67 73 62 65 67 72 65 62 65 74 73 } //1 curiousness forureningsbegrebets
		$a_81_6 = {5c 69 6e 64 61 7a 69 6e 65 2e 64 6c 6c } //1 \indazine.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Guloader_SI_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {54 65 67 6c 73 74 65 6e 73 6f 76 6e 65 31 37 37 2e 75 74 74 } //1 Teglstensovne177.utt
		$a_81_1 = {41 6d 69 74 6f 74 69 63 61 6c 6c 79 2e 6b 72 79 } //1 Amitotically.kry
		$a_81_2 = {44 69 73 6b 6f 66 69 6c 65 72 73 31 36 2e 6c 72 65 } //1 Diskofilers16.lre
		$a_81_3 = {42 6f 6e 61 67 68 74 2e 62 73 73 } //1 Bonaght.bss
		$a_81_4 = {48 65 74 65 72 6f 74 69 63 2e 70 72 65 } //1 Heterotic.pre
		$a_81_5 = {4d 69 6d 62 61 72 2e 61 6e 67 } //1 Mimbar.ang
		$a_81_6 = {51 75 61 65 73 74 6f 72 73 68 69 70 33 33 2e 6d 6f 6c } //1 Quaestorship33.mol
		$a_81_7 = {6c 75 73 6b 65 72 73 2e 6e 6f 6e } //1 luskers.non
		$a_81_8 = {6f 6c 69 67 6f 70 6c 61 73 6d 69 61 2e 62 65 6e } //1 oligoplasmia.ben
		$a_81_9 = {73 63 6f 6f 70 2e 73 61 6d } //1 scoop.sam
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}
rule Trojan_Win32_Guloader_SI_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 45 72 6f 64 65 72 69 6e 67 31 36 32 5c 4b 6c 65 6d 6d 65 6c 73 65 73 5c 62 6f 67 65 6e 73 65 72 6e 65 73 } //1 \Erodering162\Klemmelses\bogensernes
		$a_81_1 = {4e 6f 6e 61 62 73 6f 6c 75 74 65 6e 65 73 73 } //1 Nonabsoluteness
		$a_81_2 = {5c 61 67 72 6f 6e 6f 6d 65 5c 6d 6f 62 75 6c 61 5c 6e 69 74 74 65 6e 73 5c 45 6e 67 65 6c 73 68 6f 6c 6d 31 35 32 } //1 \agronome\mobula\nittens\Engelsholm152
		$a_81_3 = {61 6e 74 69 64 61 6e 63 69 6e 67 2e 61 73 74 } //1 antidancing.ast
		$a_81_4 = {6f 75 74 6d 69 72 61 63 6c 65 2e 6e 6f 6e } //1 outmiracle.non
		$a_81_5 = {73 79 6e 65 63 74 69 63 73 2e 6d 65 73 } //1 synectics.mes
		$a_81_6 = {75 72 75 74 75 2e 64 61 6c } //1 urutu.dal
		$a_81_7 = {6d 61 61 6c 66 6f 72 6d 75 6c 65 72 69 6e 67 5c 42 65 64 61 6d 70 32 31 5c 49 6e 64 72 79 6b 6e 69 6e 67 73 32 32 30 5c 72 65 63 6b 69 6e 67 } //1 maalformulering\Bedamp21\Indryknings220\recking
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}