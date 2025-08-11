
rule Trojan_Win32_Guloader_AO_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6b 6f 6d 6d 75 6e 69 6b 61 74 69 6f 6e 73 6b 6f 6d 6d 61 6e 64 6f 2e 72 65 74 } //1 kommunikationskommando.ret
		$a_81_1 = {41 6b 6b 76 69 73 69 74 69 76 74 2e 6c 6e 6b } //1 Akkvisitivt.lnk
		$a_81_2 = {46 69 62 65 72 74 69 6c 73 6b 75 64 2e 48 6f 6d } //1 Fibertilskud.Hom
		$a_81_3 = {50 52 4f 47 52 41 4d 46 49 4c 45 53 25 5c 49 6e 66 61 6e 74 65 72 69 65 6e 68 65 64 65 72 32 2e 66 61 6e } //1 PROGRAMFILES%\Infanterienheder2.fan
		$a_81_4 = {42 69 6e 64 65 6d 69 64 64 65 6c 65 74 73 31 32 30 2e 64 6c 6c } //1 Bindemiddelets120.dll
		$a_81_5 = {53 6e 69 67 6c 62 65 32 32 35 2e 48 41 4e } //1 Sniglbe225.HAN
		$a_81_6 = {49 6e 6b 61 6d 69 6e 61 74 69 6f 6e 65 6e 73 2e 73 74 72 } //1 Inkaminationens.str
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}