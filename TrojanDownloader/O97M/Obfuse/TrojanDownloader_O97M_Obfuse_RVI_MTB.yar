
rule TrojanDownloader_O97M_Obfuse_RVI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_00_1 = {2e 52 75 6e 20 28 61 73 64 73 61 64 73 61 64 77 71 64 77 71 64 71 77 28 78 78 29 29 } //1 .Run (asdsadsadwqdwqdqw(xx))
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 30 37 22 29 29 } //1 Application.Wait (Now + TimeValue("0:00:07"))
		$a_00_3 = {67 68 68 66 67 66 67 64 73 66 61 73 2e 52 65 67 44 65 6c 65 74 65 20 28 61 73 64 73 61 64 73 61 64 77 71 64 77 71 64 71 77 28 73 78 78 29 29 } //1 ghhfgfgdsfas.RegDelete (asdsadsadwqdwqdqw(sxx))
		$a_00_4 = {73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 73 74 72 2c 20 69 2c 20 32 29 29 20 2d 20 32 32 29 } //1 sStr + Chr(CLng("&H" & Mid(str, i, 2)) - 22)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}