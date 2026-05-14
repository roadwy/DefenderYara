
rule _#PUA_Block_SweetIM{
	meta:
		description = "!#PUA:Block:SweetIM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 52 41 52 20 49 6e 73 74 61 6c 6c 65 72 20 62 79 20 53 77 65 65 74 50 61 63 6b 73 } //1 WinRAR Installer by SweetPacks
		$a_81_1 = {53 77 65 65 74 49 4d 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 20 4c 74 64 } //1 SweetIM Technologies Ltd
		$a_81_2 = {53 77 65 65 74 53 44 4d } //1 SweetSDM
		$a_81_3 = {4d 61 6b 65 20 53 77 65 65 74 50 61 63 6b 73 20 6d 79 20 64 65 66 61 75 6c 74 20 73 65 61 72 63 68 20 65 6e 67 69 6e 65 } //1 Make SweetPacks my default search engine
		$a_81_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*-100+(#a_81_5  & 1)*-100) >=4
 
}
rule _#PUA_Block_SweetIM_2{
	meta:
		description = "!#PUA:Block:SweetIM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {50 44 46 43 6f 6e 76 65 72 74 65 72 2e 65 78 65 } //1 PDFConverter.exe
		$a_81_1 = {50 44 46 43 6f 6e 76 65 72 74 65 72 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 PDFConverterInstaller.exe
		$a_81_2 = {62 61 62 79 6c 6f 6e 2d 6f 66 66 65 72 2d 62 75 74 74 6f 6e 73 } //1 babylon-offer-buttons
		$a_81_3 = {62 61 62 79 6c 6f 6e 2d 73 6b 69 70 2d 62 75 74 74 6f 6e } //1 babylon-skip-button
		$a_81_4 = {46 6f 78 54 61 62 20 50 44 46 20 43 6f 6e 76 65 72 74 65 72 } //1 FoxTab PDF Converter
		$a_81_5 = {6f 66 66 65 72 5f 68 74 6d 6c 2e 74 78 74 } //1 offer_html.txt
		$a_81_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*-100+(#a_81_7  & 1)*-100) >=6
 
}