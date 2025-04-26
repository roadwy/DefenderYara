
rule TrojanDownloader_Win32_Rochap_K{
	meta:
		description = "TrojanDownloader:Win32/Rochap.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8a 5c 38 ff 80 e3 0f 8b 45 f4 8a 44 30 ff 24 0f 32 d8 80 f3 0a } //1
		$a_01_1 = {63 6f 6e 74 61 64 6f 72 2e 64 6c 6c 00 63 61 72 72 65 67 61 72 00 } //1 潣瑮摡牯搮汬挀牡敲慧r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}