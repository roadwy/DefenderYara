
rule TrojanDownloader_Win32_Zlob_gen_CF{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {47 c6 84 24 ?? ?? ?? ?? (45|54) 90 09 0f 00 c6 84 24 } //1
		$a_03_1 = {ff 47 c6 85 ?? ?? ff ff 45 90 09 05 00 c6 85 ?? ?? ff } //1
		$a_01_2 = {6d 67 72 74 2e 64 6c 6c 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}