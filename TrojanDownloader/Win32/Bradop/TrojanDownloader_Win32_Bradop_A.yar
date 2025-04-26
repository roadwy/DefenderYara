
rule TrojanDownloader_Win32_Bradop_A{
	meta:
		description = "TrojanDownloader:Win32/Bradop.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff b9 01 04 00 00 e8 ?? ?? ?? ff 8b 85 f0 f9 ff ff b9 0f 00 00 00 33 d2 e8 ?? ?? ?? ff 8b 85 f4 f9 ff ff 50 b8 ?? ?? ?? ?? 8d 95 ec f9 ff ff e8 ?? ?? ?? ff 8b 95 ec f9 ff ff } //10
		$a_03_1 = {ff b9 01 04 00 00 e8 ?? ?? ?? ff 8b 85 00 fa ff ff b9 0f 00 00 00 33 d2 e8 ?? ?? ?? ff 8b 85 04 fa ff ff 50 8d 95 fc f9 ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 95 fc f9 ff ff } //10
		$a_00_2 = {08 00 48 00 54 00 4d 00 4c 00 46 00 49 00 4c 00 45 00 06 00 58 00 57 00 52 00 45 00 47 00 43 00 } //1
		$a_02_3 = {70 46 3a 46 2f 46 2f [0-02] 32 [0-02] 30 [0-02] 30 [0-02] 2e [0-02] 39 [0-02] 38 [0-02] 2e [0-02] 31 [0-02] 33 [0-02] 36 [0-02] 2e [0-02] 37 [0-02] 32 } //9
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_00_2  & 1)*1+(#a_02_3  & 1)*9) >=10
 
}