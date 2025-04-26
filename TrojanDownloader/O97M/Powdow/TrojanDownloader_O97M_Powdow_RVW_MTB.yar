
rule TrojanDownloader_O97M_Powdow_RVW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 70 20 62 79 70 61 73 73 20 2d 65 20 22 20 2b 20 70 29 } //1 CreateObject("WScript.Shell").Run ("powershell -nop -ep bypass -e " + p)
		$a_01_1 = {70 20 3d 20 70 20 2b 20 22 53 41 41 79 41 43 73 41 4f 41 42 6d 41 47 49 41 62 51 41 78 41 46 59 41 4c 77 42 6c 41 44 63 41 59 77 41 34 41 47 59 41 56 41 42 71 41 46 6b 41 5a 67 22 } //1 p = p + "SAAyACsAOABmAGIAbQAxAFYALwBlADcAYwA4AGYAVABqAFkAZg"
		$a_01_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}