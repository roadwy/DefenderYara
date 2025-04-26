
rule TrojanDropper_O97M_Hancitor_AM_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.AM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 63 62 64 66 20 3d 20 62 63 62 64 66 20 26 20 6a 6a } //1 bcbdf = bcbdf & jj
		$a_01_1 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 66 64 77 65 73 64 66 } //1 Call ThisDocument.hfdwesdf
		$a_01_2 = {43 61 6c 6c 20 6d 69 6b 6f 28 62 63 62 64 66 2c 20 22 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 29 } //1 Call miko(bcbdf, "d" & "o" & "c")
		$a_01_3 = {76 76 20 3d 20 22 70 2e 22 20 26 20 76 66 } //1 vv = "p." & vf
		$a_01_4 = {43 61 6c 6c 20 6d 6d 28 22 6b 75 6b 75 6d 61 72 31 73 2e 72 22 20 26 20 70 78 63 29 } //1 Call mm("kukumar1s.r" & pxc)
		$a_01_5 = {43 61 6c 6c 20 6d 6d 28 22 68 22 20 26 20 22 74 22 20 26 20 6b 6c 78 29 } //1 Call mm("h" & "t" & klx)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}