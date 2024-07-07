
rule Trojan_BAT_FormBook_DTM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.DTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 20 c0 0f 00 00 28 90 01 03 0a 72 05 00 00 70 28 90 01 03 0a 28 90 01 03 06 0b 72 4e 03 00 70 28 90 01 03 06 0c 06 07 90 00 } //1
		$a_01_1 = {58 00 6d 00 6c 00 4e 00 61 00 6d 00 65 00 73 00 70 00 61 00 63 00 65 00 45 00 6e 00 63 00 6f 00 64 00 65 00 72 00 } //1 XmlNamespaceEncoder
		$a_01_2 = {44 65 66 69 6e 65 42 79 56 61 6c 54 53 74 72 52 65 6d 6f 74 69 6e 67 53 65 72 76 69 63 65 73 } //1 DefineByValTStrRemotingServices
		$a_01_3 = {53 70 6c 69 74 } //1 Split
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}