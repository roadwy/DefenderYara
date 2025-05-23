
rule TrojanDownloader_O97M_IcedID_PCJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 4e 75 6d 62 65 72 20 3d 20 46 72 65 65 46 69 6c 65 } //1 FileNumber = FreeFile
		$a_02_1 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 53 70 63 28 [0-0f] 29 } //1
		$a_00_2 = {46 69 6c 65 43 6f 70 79 } //1 FileCopy
		$a_00_3 = {49 66 20 28 78 25 20 3e 20 36 34 20 41 6e 64 20 78 25 20 3c 20 39 31 29 20 4f 72 20 28 78 25 20 3e 20 39 36 20 41 6e 64 20 78 25 20 3c 20 31 32 33 29 } //1 If (x% > 64 And x% < 91) Or (x% > 96 And x% < 123)
		$a_00_4 = {49 66 20 78 25 20 3c 20 39 37 20 41 6e 64 20 78 25 20 3e 20 38 33 20 54 68 65 6e 20 78 25 20 3d 20 78 25 20 2b 20 32 36 20 45 6c 73 65 20 49 66 20 78 25 20 3c 20 36 35 20 54 68 65 6e 20 78 25 20 3d 20 78 25 20 2b 20 32 36 } //1 If x% < 97 And x% > 83 Then x% = x% + 26 Else If x% < 65 Then x% = x% + 26
		$a_02_5 = {4d 69 64 24 28 [0-0a] 24 2c 20 74 74 2c 20 31 29 20 3d 20 43 68 72 24 28 78 25 29 } //1
		$a_00_6 = {3d 20 22 70 2c 3a 2c 5c 2c 6a 2c 76 2c 61 2c 71 2c 62 2c 6a 2c 66 2c 5c 2c 66 2c 6c 2c 66 2c 67 2c 72 2c 7a 2c 33 2c 32 2c 5c 2c 7a 2c 66 2c 75 2c 67 2c 6e 2c 2e 2c 72 2c 6b 2c 72 2c } //1 = "p,:,\,j,v,a,q,b,j,f,\,f,l,f,g,r,z,3,2,\,z,f,u,g,n,.,r,k,r,
		$a_00_7 = {3d 20 22 50 2c 3a 2c 5c 2c 68 2c 66 2c 72 2c 65 2c 66 2c 5c 2c 63 2c 68 2c 6f 2c 79 2c 76 2c 70 2c 5c 2c 76 2c 61 2c 2e 2c 70 2c 62 2c 7a 2c } //1 = "P,:,\,h,f,r,e,f,\,c,h,o,y,v,p,\,v,a,.,p,b,z,
		$a_00_8 = {3d 20 22 50 2c 3a 2c 5c 2c 68 2c 66 2c 72 2c 65 2c 66 2c 5c 2c 63 2c 68 2c 6f 2c 79 2c 76 2c 70 2c 5c 2c 76 2c 61 2c 2e 2c 75 2c 67 2c 7a 2c 79 2c } //1 = "P,:,\,h,f,r,e,f,\,c,h,o,y,v,p,\,v,a,.,u,g,z,y,
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}