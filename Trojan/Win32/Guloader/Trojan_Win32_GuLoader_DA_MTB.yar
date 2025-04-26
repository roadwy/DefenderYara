
rule Trojan_Win32_GuLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {69 73 62 6a 65 72 67 65 74 73 5c 62 72 61 6e 64 69 6e 73 70 65 6b 74 72 65 72 6e 65 5c 72 65 67 6e 65 6e 73 } //1 isbjergets\brandinspektrerne\regnens
		$a_81_1 = {4c 61 75 72 62 72 6b 72 61 6e 73 65 6e 65 2e 70 72 69 } //1 Laurbrkransene.pri
		$a_81_2 = {53 76 65 6c 6e 69 6e 67 65 72 73 2e 69 6e 69 } //1 Svelningers.ini
		$a_81_3 = {6f 70 66 72 65 6c 73 65 73 5c 74 69 70 70 65 6c 61 64 5c 67 65 6e 65 72 61 6c 69 6e 64 65 72 73 } //1 opfrelses\tippelad\generalinders
		$a_81_4 = {67 65 72 6d 61 79 6e 65 2e 74 78 74 } //1 germayne.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_DA_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 00 6e 00 69 00 6e 00 76 00 61 00 64 00 61 00 62 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 uninvadable.exe
		$a_01_1 = {45 00 6e 00 65 00 72 00 67 00 69 00 73 00 69 00 6e 00 67 00 2e 00 62 00 69 00 6e 00 } //1 Energising.bin
		$a_01_2 = {53 00 75 00 70 00 65 00 72 00 65 00 76 00 69 00 64 00 65 00 6e 00 63 00 65 00 2e 00 69 00 6e 00 69 00 } //1 Superevidence.ini
		$a_01_3 = {45 00 64 00 64 00 69 00 65 00 2d 00 43 00 4c 00 49 00 2e 00 65 00 78 00 65 00 } //1 Eddie-CLI.exe
		$a_01_4 = {48 00 64 00 65 00 72 00 6b 00 72 00 6f 00 6e 00 65 00 74 00 32 00 33 00 37 00 2e 00 6c 00 6e 00 6b 00 } //1 Hderkronet237.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_Win32_GuLoader_DA_MTB_3{
	meta:
		description = "Trojan:Win32/GuLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 12 00 00 "
		
	strings :
		$a_81_0 = {64 69 73 74 65 6e 73 69 6c 65 20 70 72 65 74 74 69 6e 65 73 73 20 64 65 63 6c 61 72 61 74 69 76 65 73 } //10 distensile prettiness declaratives
		$a_81_1 = {61 66 66 61 6c 64 73 62 65 68 61 6e 64 6c 69 6e 67 73 73 79 73 74 65 6d } //10 affaldsbehandlingssystem
		$a_81_2 = {63 61 72 6c 6f 74 20 76 69 72 67 69 6e 69 61 20 6f 6d 73 6b 72 69 76 65 72 } //10 carlot virginia omskriver
		$a_81_3 = {5c 4b 6e 6f 78 76 69 6c 6c 69 74 65 5c 4c 6f 6f 73 65 6e 65 64 5c 41 66 67 61 61 65 74 5c 54 72 6b 6b 65 72 65 6e 73 } //10 \Knoxvillite\Loosened\Afgaaet\Trkkerens
		$a_81_4 = {54 69 6c 6b 65 6e 64 65 67 69 76 65 6c 73 65 6e 20 42 6c 65 62 75 6b 73 65 72 20 53 6e 6f 77 62 69 72 64 73 } //10 Tilkendegivelsen Blebukser Snowbirds
		$a_81_5 = {67 72 61 76 69 74 61 74 69 6f 6e 20 6b 61 6f 6c 69 6e 69 7a 65 64 20 63 61 6d 70 75 6c 69 74 72 6f 70 61 6c } //10 gravitation kaolinized campulitropal
		$a_81_6 = {66 65 6a 6c 76 75 72 64 65 72 65 74 20 7a 6f 6f 66 69 6c 69 20 70 61 72 61 67 6c 6f 73 73 61 } //10 fejlvurderet zoofili paraglossa
		$a_81_7 = {73 61 6d 6d 65 6e 74 72 6b 6e 69 6e 67 73 20 73 61 6d 6c 65 6c 69 6e 73 65 72 } //10 sammentrknings samlelinser
		$a_81_8 = {67 61 75 73 73 66 75 6e 6b 74 69 6f 6e 65 72 6e 65 73 20 6d 69 73 72 65 63 6b 6f 6e 69 6e 67 } //10 gaussfunktionernes misreckoning
		$a_81_9 = {6d 6f 75 6c 61 67 65 20 69 6e 64 6c 67 6e 69 6e 67 65 72 6e 65 20 70 6f 6c 74 72 6f 6f 6e 69 73 68 } //1 moulage indlgningerne poltroonish
		$a_81_10 = {61 70 70 6c 69 61 6e 63 65 20 73 6c 61 67 67 69 6e 67 20 70 6f 6c 6c 79 61 6e 6e 61 } //1 appliance slagging pollyanna
		$a_81_11 = {6b 75 62 69 6b 69 6e 64 68 6f 6c 64 65 74 20 61 62 61 63 61 74 65 20 67 65 6e 65 72 69 6e 64 72 65 72 } //1 kubikindholdet abacate generindrer
		$a_81_12 = {5c 52 65 63 6f 73 74 75 6d 65 64 5c 4e 69 6b 6b 65 6c 68 65 66 74 65 64 65 73 } //1 \Recostumed\Nikkelheftedes
		$a_81_13 = {4b 6f 6e 66 69 73 6b 65 72 65 64 65 } //1 Konfiskerede
		$a_81_14 = {69 6e 61 63 63 75 72 61 63 79 20 67 61 73 63 6f 6e 20 69 6e 64 65 73 6c 75 74 6e 69 6e 67 65 72 73 } //1 inaccuracy gascon indeslutningers
		$a_81_15 = {62 6c 6f 6b 6e 69 76 65 61 75 65 72 6e 65 73 20 75 6e 61 76 6e 67 69 76 65 74 } //1 blokniveauernes unavngivet
		$a_81_16 = {62 65 72 65 67 6e 65 6c 69 67 65 73 } //1 beregneliges
		$a_81_17 = {62 75 6e 64 61 66 73 74 61 6e 64 65 6e 65 73 } //1 bundafstandenes
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*10+(#a_81_8  & 1)*10+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1) >=11
 
}