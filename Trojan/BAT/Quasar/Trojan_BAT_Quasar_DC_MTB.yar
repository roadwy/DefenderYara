
rule Trojan_BAT_Quasar_DC_MTB{
	meta:
		description = "Trojan:BAT/Quasar.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 ff b6 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 49 01 00 00 2b } //10
		$a_01_1 = {78 43 6c 69 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 xClient.Properties.Resources.resources
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //1 Base64String
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}