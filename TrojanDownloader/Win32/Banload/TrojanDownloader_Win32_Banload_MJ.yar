
rule TrojanDownloader_Win32_Banload_MJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.MJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 38 ff 89 45 ?? b8 ?? ?? ?? ?? 0f b6 44 18 ff 89 45 ?? 8d 45 ?? 8b 55 ?? 2b 55 } //1
		$a_01_1 = {0b 54 46 72 6d 53 70 6f 6f 6c 56 41 } //1 吋牆卭潰汯䅖
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}