
rule TrojanDownloader_O97M_Hancitor_SML_MTB{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.SML!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 6c 78 20 3d 20 22 74 22 } //1 klx = "t"
		$a_01_1 = {43 61 6c 6c 20 6d 6d 28 22 68 22 20 26 20 22 74 22 20 26 20 6b 6c 78 29 } //1 Call mm("h" & "t" & klx)
		$a_01_2 = {76 76 20 3d 20 22 70 2e 22 20 26 20 76 66 } //1 vv = "p." & vf
		$a_01_3 = {26 20 22 5c 6d 6f 65 78 78 22 20 26 20 70 6c 66 20 26 20 22 62 22 20 26 20 22 69 22 20 26 20 22 6e 22 2c } //1 & "\moexx" & plf & "b" & "i" & "n",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}