
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