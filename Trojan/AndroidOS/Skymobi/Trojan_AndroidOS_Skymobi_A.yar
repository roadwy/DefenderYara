
rule Trojan_AndroidOS_Skymobi_A{
	meta:
		description = "Trojan:AndroidOS/Skymobi.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 64 64 46 69 6c 65 4c 6f 63 61 74 69 6f 6e 49 6e 66 6f 73 } //1 addFileLocationInfos
		$a_01_1 = {57 49 46 49 6f 72 4d 4f 42 49 4c 45 } //1 WIFIorMOBILE
		$a_01_2 = {41 70 70 43 68 65 63 6b 72 65 74 72 69 65 76 65 58 6d 6c } //1 AppCheckretrieveXml
		$a_01_3 = {64 61 6e 67 4c 65 42 61 63 6b 55 72 6c } //1 dangLeBackUrl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}