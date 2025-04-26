
rule TrojanDownloader_O97M_Bladabindi{
	meta:
		description = "TrojanDownloader:O97M/Bladabindi,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 20 3d 20 22 68 74 74 70 3a 2f 2f 69 63 62 67 2d 69 71 2e 63 6f 6d 2f 53 63 72 69 70 74 73 2f 6b 69 6e 65 74 69 63 73 2f 64 72 6f 69 64 73 2f 67 61 6e 67 72 69 6e 69 2f 75 70 6c 6f 61 64 2f 72 65 67 7a 61 62 2e 65 78 65 22 } //1 e = "http://icbg-iq.com/Scripts/kinetics/droids/gangrini/upload/regzab.exe"
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 52 65 70 6c 61 63 65 28 63 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 73 72 70 72 2f 6c 6f 67 6f 31 77 2e 70 6e 67 22 2c 20 65 29 29 2c 20 30 2c 20 54 72 75 65 } //1 CreateObject("WScript.Shell").Run (Replace(c, "https://www.google.com/images/srpr/logo1w.png", e)), 0, True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}