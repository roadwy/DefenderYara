
rule TrojanDownloader_O97M_Obfuse_PYRX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PYRX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {28 30 2c 20 22 6f 70 65 6e 22 2c 20 6b 6f 6b 6f 2c 20 22 68 22 20 5f } //1 (0, "open", koko, "h" _
		$a_01_1 = {2b 20 22 77 22 20 2b 20 22 2e 22 20 2b 20 22 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 2f 68 77 64 69 6e 6e 77 73 68 64 77 64 77 64 77 77 64 77 6d 71 77 68 64 61 22 2c 20 5f } //1 + "w" + "." + "b" + "i" + "t" + "l" + "y" + "." + "c" + "o" + "m/hwdinnwshdwdwdwwdwmqwhda", _
		$a_01_2 = {22 25 70 75 62 6c 69 63 25 22 20 5f } //1 "%public%" _
		$a_01_3 = {22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 5f } //1 "Shell32.dll" _
		$a_01_4 = {41 6c 69 61 73 20 5f } //1 Alias _
		$a_01_5 = {22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 5f } //1 "ShellExecuteA" _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}