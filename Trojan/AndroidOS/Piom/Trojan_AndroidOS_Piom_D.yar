
rule Trojan_AndroidOS_Piom_D{
	meta:
		description = "Trojan:AndroidOS/Piom.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 74 61 6e 74 41 70 70 57 6f 72 6b 53 74 72 69 6e 67 } //2 ConstantAppWorkString
		$a_01_1 = {50 4b 5f 49 53 5f 43 4c 49 50 5f 45 4e 41 42 4c 45 44 } //2 PK_IS_CLIP_ENABLED
		$a_01_2 = {50 41 59 4c 4f 41 44 5f 55 50 44 41 54 45 5f 55 52 4c } //2 PAYLOAD_UPDATE_URL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}