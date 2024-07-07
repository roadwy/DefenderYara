
rule Trojan_WinNT_GBinHost_A_ldr{
	meta:
		description = "Trojan:WinNT/GBinHost.A!ldr,SIGNATURE_TYPE_JAVAHSTR_EXT,20 00 1c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 6e 65 74 2f 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e } //2 java/net/URLConnection
		$a_01_1 = {6a 61 76 61 2f 75 74 69 6c 2f 45 6e 75 6d 65 72 61 74 69 6f 6e } //2 java/util/Enumeration
		$a_01_2 = {6a 61 76 61 2f 75 74 69 6c 2f 7a 69 70 2f 5a 69 70 45 6e 74 72 79 } //2 java/util/zip/ZipEntry
		$a_01_3 = {6a 61 76 61 2f 69 6f 2f 42 75 66 66 65 72 65 64 4f 75 74 70 75 74 53 74 72 65 61 6d } //2 java/io/BufferedOutputStream
		$a_01_4 = {6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 74 69 6d 65 } //2 java/lang/Runtime
		$a_01_5 = {67 65 74 52 65 73 6f 75 72 63 65 41 73 53 74 72 65 61 6d } //2 getResourceAsStream
		$a_00_6 = {68 6f 73 74 } //2 host
		$a_00_7 = {73 79 73 5f 6e 61 6d 65 } //2 sys_name
		$a_00_8 = {68 6f 73 74 5f 6e 61 6d 65 } //2 host_name
		$a_01_9 = {2a b4 b6 b6 2a b4 b8 } //10
		$a_01_10 = {2a 59 b4 bb 5a 5f b8 b7 2a b4 b6 b6 b5 } //10
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10) >=28
 
}