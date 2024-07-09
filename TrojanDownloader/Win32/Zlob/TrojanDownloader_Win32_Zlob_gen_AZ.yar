
rule TrojanDownloader_Win32_Zlob_gen_AZ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 7e 01 3a 88 9d ?? ?? ff ff b9 ff 00 00 00 8d bd ?? ?? ff ff f3 ab 66 ab 88 5d ff aa 89 5d ?? 74 31 8d 85 ?? ?? ff ff 50 53 53 6a 25 53 ff 15 ?? ?? ?? ?? 56 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 68 ?? ?? ?? ?? 50 ff 15 } //1
		$a_01_1 = {39 5d 14 5f 5e 5b 74 10 } //1 崹弔孞ၴ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}