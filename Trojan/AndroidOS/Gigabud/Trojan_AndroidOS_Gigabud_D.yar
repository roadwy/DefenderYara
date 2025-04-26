
rule Trojan_AndroidOS_Gigabud_D{
	meta:
		description = "Trojan:AndroidOS/Gigabud.D,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 76 69 72 62 6f 78 2f 53 74 75 62 41 70 70 } //2 Lvirbox/StubApp
		$a_01_1 = {6c 30 64 66 32 61 61 65 34 24 6a 6e 74 6d } //1 l0df2aae4$jntm
		$a_01_2 = {49 36 37 36 65 66 62 35 62 5f 30 33 } //1 I676efb5b_03
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_AndroidOS_Gigabud_D_2{
	meta:
		description = "Trojan:AndroidOS/Gigabud.D,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 45 53 53 41 47 45 5f 53 54 41 52 54 5f 55 50 4c 4f 41 44 } //2 MESSAGE_START_UPLOAD
		$a_01_1 = {73 74 61 72 74 52 65 63 6f 72 64 41 6e 64 55 70 6c 6f 61 64 } //2 startRecordAndUpload
		$a_01_2 = {6f 6e 53 63 72 65 65 6e 44 61 74 61 45 6e 63 6f 64 65 64 } //2 onScreenDataEncoded
		$a_01_3 = {77 68 6f 70 65 6e 75 72 6c 3a } //2 whopenurl:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}