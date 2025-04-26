
rule Trojan_Win64_Lotok_NIT_MTB{
	meta:
		description = "Trojan:Win64/Lotok.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {6e 74 67 2e 64 61 74 } //2 ntg.dat
		$a_01_1 = {73 62 73 2e 64 61 74 } //2 sbs.dat
		$a_01_2 = {55 6e 70 61 63 6b 44 44 45 6c 50 61 72 61 6d } //2 UnpackDDElParam
		$a_01_3 = {47 64 69 70 43 72 65 61 74 65 42 69 74 6d 61 70 46 72 6f 6d 48 42 49 54 4d 41 50 } //2 GdipCreateBitmapFromHBITMAP
		$a_01_4 = {44 65 61 63 74 69 76 61 74 65 41 63 74 43 74 78 } //1 DeactivateActCtx
		$a_01_5 = {57 49 4e 53 50 4f 4f 4c 2e 44 52 56 } //1 WINSPOOL.DRV
		$a_01_6 = {41 56 43 44 6f 77 6e 6c 6f 61 64 65 72 } //1 AVCDownloader
		$a_01_7 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}