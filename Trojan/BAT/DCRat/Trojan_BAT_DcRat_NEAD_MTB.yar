
rule Trojan_BAT_DcRat_NEAD_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 08 00 00 "
		
	strings :
		$a_01_0 = {31 36 34 33 37 38 39 66 2d 31 37 62 39 2d 34 33 65 36 2d 38 37 37 33 2d 35 34 31 35 34 66 62 65 61 63 62 62 } //5 1643789f-17b9-43e6-8773-54154fbeacbb
		$a_01_1 = {6d 65 64 69 61 2e 65 78 65 } //5 media.exe
		$a_01_2 = {74 65 6c 6b 6f 6d 5f 70 72 65 76 69 65 77 } //2 telkom_preview
		$a_01_3 = {4d 65 64 69 61 20 50 61 79 6d 65 6e 74 } //2 Media Payment
		$a_01_4 = {73 61 6c 61 68 5f 6e 6f 6e 74 61 67 6c 69 73 5f 6b 6f 6c 65 6b 74 69 66 5f 61 72 61 } //2 salah_nontaglis_kolektif_ara
		$a_01_5 = {70 65 6d 61 6b 61 69 61 6e } //2 pemakaian
		$a_01_6 = {74 78 74 70 61 73 73 77 6f 72 64 } //2 txtpassword
		$a_01_7 = {57 72 69 74 65 52 61 77 44 61 74 61 54 6f 54 78 74 46 69 6c 65 32 5f 52 50 49 5f 65 70 6f 73 } //2 WriteRawDataToTxtFile2_RPI_epos
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=22
 
}