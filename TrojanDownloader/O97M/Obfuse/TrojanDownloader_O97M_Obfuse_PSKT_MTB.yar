
rule TrojanDownloader_O97M_Obfuse_PSKT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PSKT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 71 49 4d 45 4d 6f 64 65 48 61 6e 67 75 6c 46 75 6c 6c 2e 78 73 6c 22 29 } //1 = .CreateTextFile(Environ("ALLUSERSPROFILE") & "\qIMEModeHangulFull.xsl")
		$a_01_1 = {3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 22 } //1 = "Thank You!"
		$a_01_2 = {2c 20 2c 20 22 47 6f 6f 64 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 , , "Good", Err.HelpFile, Err.HelpContext
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 CreateObject("Scripting.FileSystemObject")
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 68 65 64 75 6c 65 2e 53 65 72 76 69 63 65 22 29 } //1 = CreateObject("Schedule.Service")
		$a_01_5 = {2e 47 65 74 46 6f 6c 64 65 72 28 22 22 29 } //1 .GetFolder("")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}