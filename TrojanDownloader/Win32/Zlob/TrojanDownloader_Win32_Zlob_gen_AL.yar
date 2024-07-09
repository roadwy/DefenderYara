
rule TrojanDownloader_Win32_Zlob_gen_AL{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {85 c0 75 14 68 2c 01 00 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 56 8b 74 24 08 a3 ?? ?? ?? ?? 8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3 } //1
		$a_02_1 = {80 44 24 08 64 56 8b 35 ?? ?? ?? ?? 85 f6 57 75 16 68 2c 01 00 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b f0 8b 7c 24 0c 89 35 ?? ?? ?? ?? 8a 17 84 d2 8b ce 74 10 2b fe 32 54 24 10 88 11 41 8a 14 0f 84 d2 75 f2 5f 8b c6 c6 01 00 5e c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}