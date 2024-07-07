
rule Trojan_AndroidOS_Anserver_A{
	meta:
		description = "Trojan:AndroidOS/Anserver.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {39 43 6b 4f 72 43 33 32 75 49 33 32 37 57 42 44 37 6e 5f 5f } //1 9CkOrC32uI327WBD7n__
		$a_01_1 = {37 78 42 4e 7a 4b 46 43 7a 4b 46 57 39 49 69 57 } //1 7xBNzKFCzKFW9IiW
		$a_01_2 = {65 77 61 72 30 31 } //1 ewar01
		$a_01_3 = {77 61 72 70 65 61 63 65 } //1 warpeace
		$a_01_4 = {6f 6e 47 65 74 41 70 6b 5f 49 6e 73 74 61 6c 6c 5f 76 65 72 73 69 6f 6e 5f 69 64 } //1 onGetApk_Install_version_id
		$a_01_5 = {38 43 42 6f 7a 4b 69 54 72 74 67 64 63 78 42 4e 75 74 6b 45 38 6b 4d 43 7a 4b 46 4e 48 78 4d 4f 4b 43 52 44 } //1 8CBozKiTrtgdcxBNutkE8kMCzKFNHxMOKCRD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}