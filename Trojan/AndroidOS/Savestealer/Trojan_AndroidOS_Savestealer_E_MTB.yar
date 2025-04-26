
rule Trojan_AndroidOS_Savestealer_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Savestealer.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 43 68 65 63 6b 5f 49 6e 74 65 72 6e 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e } //1 _Check_Internet_Connection
		$a_01_1 = {5f 75 70 6c 6f 61 64 54 6f 53 65 72 76 65 72 5f 72 65 71 75 65 73 74 5f 6c 69 73 74 65 6e 65 72 } //1 _uploadToServer_request_listener
		$a_01_2 = {69 6e 69 74 69 61 6c 69 7a 65 4c 6f 67 69 63 } //1 initializeLogic
		$a_01_3 = {53 74 72 69 6e 67 46 6f 67 49 6d 70 6c } //1 StringFogImpl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}