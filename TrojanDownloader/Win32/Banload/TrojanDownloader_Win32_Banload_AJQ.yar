
rule TrojanDownloader_Win32_Banload_AJQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 d0 fb 44 00 e8 48 7e ff ff ba ?? ?? 44 00 b8 ?? ?? 44 00 e8 b9 fe ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 44 00 e8 49 ff ff ff } //1
		$a_03_1 = {a1 bc df 44 00 8b 00 e8 ?? ?? ff ff c3 [0-02] ff ff ff ff ?? 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d [0-02] 5c [0-08] 2e 65 78 65 00 [0-03] ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}