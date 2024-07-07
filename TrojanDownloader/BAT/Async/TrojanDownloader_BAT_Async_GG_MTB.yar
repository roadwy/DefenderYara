
rule TrojanDownloader_BAT_Async_GG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Async.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 90 02 64 2f 41 73 79 6e 63 43 6c 69 65 6e 74 2e 65 78 65 90 00 } //1
		$a_80_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 41 73 79 6e 63 43 6c 69 65 6e 74 2e 65 78 65 } //C:\Users\Admin\Desktop\AsyncClient.exe  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}