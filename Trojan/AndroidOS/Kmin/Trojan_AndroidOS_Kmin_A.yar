
rule Trojan_AndroidOS_Kmin_A{
	meta:
		description = "Trojan:AndroidOS/Kmin.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {73 75 2e 35 6b 33 67 2e 63 6f 6d 2f 70 6f 72 74 61 6c 2f 6d 2f 63 35 2f 90 01 01 2e 61 73 68 78 90 00 } //1
		$a_01_1 = {6b 6d 2f 74 6f 6f 6c 2f 43 6f 6e 6e 65 63 74 } //1 km/tool/Connect
		$a_01_2 = {6b 6d 2f 6c 61 75 6e 63 68 65 72 2f 41 64 64 41 64 61 70 74 65 72 24 43 72 65 61 74 65 4c 69 76 65 46 6f 6c 64 65 72 41 63 74 69 6f 6e } //1 km/launcher/AddAdapter$CreateLiveFolderAction
		$a_01_3 = {6b 6d 2f 63 68 61 72 67 65 2f 48 74 74 70 42 6f 78 } //1 km/charge/HttpBox
		$a_01_4 = {42 62 78 43 68 61 72 67 65 45 6e 67 69 6e 65 } //1 BbxChargeEngine
		$a_01_5 = {6b 6d 2f 43 68 61 72 67 65 45 6e 67 69 6e 65 } //1 km/ChargeEngine
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}