
rule TrojanDownloader_WinNT_OpenConnection_PP{
	meta:
		description = "TrojanDownloader:WinNT/OpenConnection.PP,SIGNATURE_TYPE_JAVAHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 61 70 70 6c 65 74 2f 41 70 70 6c 65 74 } //5 java/applet/Applet
		$a_01_1 = {6a 61 76 61 2f 69 6f 2f 42 79 74 65 41 72 72 61 79 49 6e 70 75 74 53 74 72 65 61 6d } //5 java/io/ByteArrayInputStream
		$a_01_2 = {6a 61 76 61 2f 6c 61 6e 67 2f 72 65 66 6c 65 63 74 2f 4d 65 74 68 6f 64 } //5 java/lang/reflect/Method
		$a_01_3 = {6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //4 java/lang/StringBuilder
		$a_01_4 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //4 getClassLoader
		$a_01_5 = {78 2a 1c 04 60 b6 10 b8 60 91 54 } //1
		$a_01_6 = {11 36 11 36 15 15 a4 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}