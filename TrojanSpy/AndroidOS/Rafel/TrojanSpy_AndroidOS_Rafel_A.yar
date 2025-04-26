
rule TrojanSpy_AndroidOS_Rafel_A{
	meta:
		description = "TrojanSpy:AndroidOS/Rafel.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {61 64 64 5f 76 69 63 74 69 6d 5f 64 65 76 69 63 65 } //1 add_victim_device
		$a_01_1 = {72 65 68 62 65 72 5f 6f 6b 75 } //1 rehber_oku
		$a_01_2 = {4c 6f 63 6b 54 68 65 53 63 72 65 65 6e } //1 LockTheScreen
		$a_01_3 = {67 65 74 5f 73 63 72 65 65 6e 73 68 6f 74 } //1 get_screenshot
		$a_01_4 = {75 70 6c 6f 61 64 5f 66 69 6c 65 5f 6e 6d } //1 upload_file_nm
		$a_01_5 = {73 77 61 67 6b 61 72 6e 61 6c 6f 76 65 73 68 61 6e 64 65 65 72 63 65 6c } //1 swagkarnaloveshandeercel
		$a_01_6 = {62 72 6c 64 5f } //1 brld_
		$a_01_7 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 69 70 74 65 64 } //1 Your files have been encripted
		$a_01_8 = {52 61 66 65 6c 2d 52 61 74 2d } //1 Rafel-Rat-
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}