
rule TrojanDownloader_WinNT_OpenConnection_PM{
	meta:
		description = "TrojanDownloader:WinNT/OpenConnection.PM,SIGNATURE_TYPE_JAVAHSTR_EXT,24 00 24 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 6e 65 74 2f 55 52 4c } //05 00  java/net/URL
		$a_01_1 = {6a 61 76 61 2f 6c 61 6e 67 2f 53 79 73 74 65 6d } //05 00  java/lang/System
		$a_01_2 = {6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //05 00  java/lang/StringBuilder
		$a_01_3 = {6a 61 76 61 2f 69 6f 2f 42 79 74 65 41 72 72 61 79 4f 75 74 70 75 74 53 74 72 65 61 6d } //04 00  java/io/ByteArrayOutputStream
		$a_01_4 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //04 00  getClassLoader
		$a_01_5 = {67 65 74 52 75 6e 74 69 6d 65 } //04 00  getRuntime
		$a_01_6 = {55 52 4c 2e 6f 70 65 6e 53 74 72 65 61 6d } //04 00  URL.openStream
		$a_01_7 = {73 65 74 50 72 6f 70 65 72 74 79 } //03 00  setProperty
		$a_01_8 = {6e 65 77 49 6e 73 74 61 6e 63 65 } //03 00  newInstance
		$a_01_9 = {75 73 65 53 79 73 74 65 6d 50 72 6f 78 69 65 73 } //00 00  useSystemProxies
	condition:
		any of ($a_*)
 
}