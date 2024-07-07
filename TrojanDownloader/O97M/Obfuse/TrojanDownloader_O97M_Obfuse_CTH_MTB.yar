
rule TrojanDownloader_O97M_Obfuse_CTH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CTH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 42 48 64 48 6c 6c 4c 28 29 } //1 Public Sub BHdHllL()
		$a_01_1 = {62 62 62 20 3d 20 4c 65 66 74 28 22 30 6a 68 39 38 37 36 35 34 33 35 36 37 39 38 37 36 35 34 33 34 35 36 37 38 36 35 34 33 32 33 35 34 36 36 37 35 34 33 35 22 2c 20 31 29 } //1 bbb = Left("0jh9876543567987654345678654323546675435", 1)
		$a_01_2 = {63 75 72 28 69 43 29 20 3d 20 41 63 74 69 76 65 43 65 6c 6c 2e 4f 66 66 73 65 74 28 69 43 2c 20 31 29 2e 56 61 6c 75 65 } //1 cur(iC) = ActiveCell.Offset(iC, 1).Value
		$a_01_3 = {78 20 3d 20 52 65 70 6c 61 63 65 28 78 2c 20 22 7a 7a 63 69 6f 73 6f 6a 79 6f 63 6c 71 6c 22 2c 20 22 22 29 } //1 x = Replace(x, "zzciosojyoclql", "")
		$a_01_4 = {43 61 6c 6c 20 6e 37 36 35 34 } //1 Call n7654
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}