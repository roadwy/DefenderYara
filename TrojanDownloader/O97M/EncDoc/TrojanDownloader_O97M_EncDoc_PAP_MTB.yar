
rule TrojanDownloader_O97M_EncDoc_PAP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {76 62 5f 6e 61 6d 65 3d 22 90 17 03 03 03 02 6e 6d 71 6d 67 6b 7a 79 } //1
		$a_01_1 = {3d 30 6e 63 62 3d 22 76 62 78 63 62 62 6e 76 62 63 76 63 7a 78 63 76 78 63 62 76 78 63 62 22 } //1 =0ncb="vbxcbbnvbcvczxcvxcbvxcb"
		$a_01_2 = {26 76 62 6e 67 68 66 67 28 32 32 31 29 26 } //1 &vbnghfg(221)&
		$a_01_3 = {63 68 72 28 78 63 64 73 67 2d 31 34 34 29 78 63 76 62 76 78 63 } //1 chr(xcdsg-144)xcvbvxc
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_PAP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 3d 73 74 72 72 65 76 65 72 73 65 28 22 63 6e 65 2d 31 6e 69 77 2d 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 5c 30 2e 31 76 } //1 x=strreverse("cne-1niw-exe.llehsrewop\0.1v
		$a_01_1 = {78 3d 78 2b 22 73 74 22 78 3d 78 2b 22 61 72 74 22 78 3d 78 2b 22 2f 6d 22 2b 22 69 22 2b 22 6e 22 70 72 65 66 69 78 31 3d 78 65 6e 64 } //1 x=x+"st"x=x+"art"x=x+"/m"+"i"+"n"prefix1=xend
		$a_01_2 = {64 3d 73 68 65 6c 6c 28 62 61 74 2c 30 29 65 6e 64 73 } //1 d=shell(bat,0)ends
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_PAP_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 63 6c 65 61 6e 22 } //1 vb_name="clean"
		$a_01_1 = {6d 73 68 74 61 22 63 61 73 65 32 67 65 74 65 6e 75 6d 6e 61 6d 65 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 64 6f 61 6b 73 6f 64 6b 73 75 65 61 73 64 77 65 75 22 65 6e 64 73 } //1 mshta"case2getenumname="http://www.bitly.com/doaksodksueasdweu"ends
		$a_01_2 = {61 6c 63 28 29 73 65 74 63 61 6c 63 3d 67 65 74 6f 62 6a 65 63 74 28 73 74 72 72 65 76 65 72 73 65 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 65 39 34 61 2d 65 63 31 31 2d 39 37 32 63 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29 29 65 6e 64 66 } //1 alc()setcalc=getobject(strreverse("000045355444-e94a-ec11-972c-02690731:wen"))endf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}