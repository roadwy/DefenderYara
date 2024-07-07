
rule TrojanDownloader_O97M_Powdow_RVX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 49 44 20 3d 20 53 68 65 6c 6c 28 22 77 73 63 72 69 70 74 20 61 70 69 68 61 6e 64 6c 65 72 2e 6a 73 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 PID = Shell("wscript apihandler.js", vbNormalFocus)
		$a_01_1 = {52 61 6e 67 65 28 22 47 4d 32 33 32 33 22 29 2e 56 61 6c 75 65 20 26 20 52 61 6e 67 65 28 22 47 4d 32 33 32 34 22 29 2e 56 61 6c 75 65 20 26 20 52 61 6e 67 65 28 22 47 4d 32 33 32 35 22 29 2e 56 61 6c 75 65 } //1 Range("GM2323").Value & Range("GM2324").Value & Range("GM2325").Value
		$a_01_2 = {52 61 6e 67 65 28 22 47 4d 32 33 32 35 22 29 2e 56 61 6c 75 65 20 3d 20 22 22 0d 0a 45 6e 64 20 53 75 62 } //1
		$a_01_3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 6d 61 63 68 69 6e 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}