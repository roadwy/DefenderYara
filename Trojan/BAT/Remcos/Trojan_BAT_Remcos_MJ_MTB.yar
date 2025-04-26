
rule Trojan_BAT_Remcos_MJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 9f b6 2b 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5a 01 00 00 95 01 00 00 ed 05 00 00 6f } //10
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_7 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}