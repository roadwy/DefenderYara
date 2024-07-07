
rule TrojanDownloader_O97M_Obfuse_KF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4e 68 28 22 61 70 70 22 20 26 20 51 79 29 20 26 20 69 20 26 20 22 70 75 74 74 79 2e 22 20 26 20 61 } //1 = Nh("app" & Qy) & i & "putty." & a
		$a_01_1 = {56 64 63 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 Vdc.createElement("b64")
		$a_01_2 = {3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 = "bin.base64"
		$a_01_3 = {3d 20 22 65 78 65 22 } //1 = "exe"
		$a_01_4 = {2e 63 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 } //1 .createTextFile(
		$a_03_5 = {3d 20 53 74 72 43 6f 6e 76 28 90 02 06 2c 20 76 62 55 6e 69 63 6f 64 65 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}