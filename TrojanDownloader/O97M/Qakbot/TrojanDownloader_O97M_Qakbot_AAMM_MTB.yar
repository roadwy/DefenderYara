
rule TrojanDownloader_O97M_Qakbot_AAMM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AAMM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 4d 69 70 6f 70 6c 61 22 29 2e 52 61 6e 67 65 28 22 47 31 30 22 29 20 3d 20 22 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73 } //1 Sheets("Mipopla").Range("G10") = "..\Popol.gors
		$a_01_1 = {53 68 65 65 74 73 28 22 4d 69 70 6f 70 6c 61 22 29 2e 52 61 6e 67 65 28 22 4b 31 38 22 29 20 3d 20 22 2e 22 20 26 20 22 64 22 20 26 20 22 61 22 20 26 20 22 74 22 } //1 Sheets("Mipopla").Range("K18") = "." & "d" & "a" & "t"
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 4d 69 70 6f 70 6c 61 22 29 2e 52 61 6e 67 65 28 22 48 31 22 29 } //1 Application.Run Sheets("Mipopla").Range("H1")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}