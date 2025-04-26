
rule TrojanDownloader_Win32_Jaik_AS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Jaik.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 35 00 31 00 2e 00 37 00 39 00 2e 00 34 00 39 00 2e 00 37 00 33 00 2f 00 } //1 http://51.79.49.73/
		$a_01_1 = {41 00 44 00 4f 00 44 00 42 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 } //1 ADODB.Stream
		$a_01_2 = {53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00 } //1 SaveToFile
		$a_01_3 = {57 00 72 00 69 00 74 00 65 00 } //1 Write
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}