
rule TrojanDownloader_BAT_Nanocore_PA1_MTB{
	meta:
		description = "TrojanDownloader:BAT/Nanocore.PA1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {2f 74 61 63 2e 66 6d 6f 70 2e 61 2f 2f 3a 73 70 74 74 68 } ///tac.fmop.a//:sptth  2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_2 = {52 65 76 65 72 73 65 54 65 78 74 } //1 ReverseText
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}