
rule TrojanDownloader_Win32_Banload_RL{
	meta:
		description = "TrojanDownloader:Win32/Banload.RL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 6d 64 20 2f 6b 20 63 3a 5c 6c 69 6e 6b [0-02] 2e 67 69 66 00 63 6d 64 20 2f 6b 20 63 3a 5c 6c 69 6e 6b [0-02] 2e 67 69 66 00 } //1
		$a_02_1 = {2e 63 6f 6d 2e 62 72 2f [0-15] 2f 76 69 64 65 6f [0-02] 2e 65 78 65 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}