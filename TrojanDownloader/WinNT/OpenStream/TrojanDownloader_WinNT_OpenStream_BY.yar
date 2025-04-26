
rule TrojanDownloader_WinNT_OpenStream_BY{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.BY,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 20 2d 73 20 22 } //1 regsvr32 -s "
		$a_01_1 = {6f 70 65 6e 53 74 72 65 61 6d } //1 openStream
		$a_01_2 = {76 61 2e 69 6f 2e 74 6d 70 64 69 72 } //1 va.io.tmpdir
		$a_01_3 = {65 78 65 63 } //1 exec
		$a_01_4 = {73 65 74 53 65 63 75 72 69 74 79 4d 61 6e 61 67 65 72 } //1 setSecurityManager
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}