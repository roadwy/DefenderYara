
rule Trojan_AndroidOS_Xolco_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Xolco.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {47 55 49 5f 53 43 41 4e 5f 46 49 4e 49 53 48 } //1 GUI_SCAN_FINISH
		$a_00_1 = {53 54 4f 50 5f 43 4f 4e 4e 45 43 54 5f 43 4f 4e 4e 45 43 54 5f 53 45 52 56 45 52 5f 46 41 49 4c } //1 STOP_CONNECT_CONNECT_SERVER_FAIL
		$a_00_2 = {53 57 5f 50 52 4f 44 55 43 54 5f 48 41 4e 44 57 41 54 45 5f 52 45 56 } //1 SW_PRODUCT_HANDWATE_REV
		$a_00_3 = {6d 55 70 64 61 74 65 48 74 74 70 43 6c 69 65 6e 74 2e 64 6f 77 6e 46 69 6c 65 } //1 mUpdateHttpClient.downFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}