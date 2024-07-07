
rule TrojanDownloader_WinNT_Banload_GA_MTB{
	meta:
		description = "TrojanDownloader:WinNT/Banload.GA!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 73 75 67 61 72 73 79 6e 63 2e 63 6f 6d 2f 70 66 2f } //1 www.sugarsync.com/pf/
		$a_00_1 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 6e 2e 6a 61 72 } //1 Users\Public\an.jar
		$a_00_2 = {3f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 3d 74 72 75 65 } //1 ?directDownload=true
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}