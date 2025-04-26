
rule TrojanDownloader_O97M_EncDoc_RSE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6c 61 6e 6b 61 72 65 63 69 70 65 73 2e 63 6f 6d 2f 6d 61 67 65 73 2e 6a 70 27 20 20 2b 20 27 67 27 90 0a 30 00 63 75 72 4c 20 20 28 27 68 74 74 70 3a 2f 2f } //1
		$a_00_1 = {43 6d 44 2e 45 78 65 20 20 2f 43 20 70 6f 57 65 52 53 68 65 4c 4c 2e 45 58 65 20 20 2d 65 78 20 42 59 50 41 73 53 20 2d 4e 6f 50 20 2d 77 20 31 } //1 CmD.Exe  /C poWeRSheLL.EXe  -ex BYPAsS -NoP -w 1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_EncDoc_RSE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 4d 64 2e 65 58 65 20 20 2f 63 20 50 6f 77 45 52 53 68 65 6c 6c 20 20 2d 65 78 20 62 79 70 41 73 73 20 2d 6e 6f 50 20 2d 77 20 31 20 69 65 58 28 20 } //1 cMd.eXe  /c PowERShell  -ex bypAss -noP -w 1 ieX( 
		$a_00_1 = {63 55 72 6c 20 20 28 27 68 74 74 70 3a 2f 2f 63 72 69 74 69 27 20 20 2b 20 27 63 64 6f 6d 65 2e 63 6f 6d 2f 63 73 27 20 20 2b 20 27 73 73 2e 27 20 20 2b 20 27 6a 70 27 20 20 2b 20 27 67 27 20 29 29 } //1 cUrl  ('http://criti'  + 'cdome.com/cs'  + 'ss.'  + 'jp'  + 'g' ))
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}