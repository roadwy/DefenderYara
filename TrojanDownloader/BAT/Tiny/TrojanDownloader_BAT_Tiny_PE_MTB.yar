
rule TrojanDownloader_BAT_Tiny_PE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_01_1 = {2d 00 6e 00 6f 00 70 00 20 00 2d 00 77 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 2d 00 65 00 } //1 -nop -w hidden -e
		$a_03_2 = {68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 6c 00 69 00 67 00 68 00 74 00 2d 00 62 00 69 00 6e 00 2e 00 74 00 6b 00 2f 00 72 00 61 00 77 00 2f 00 } //1
		$a_01_3 = {66 00 75 00 64 00 2e 00 65 00 78 00 65 00 } //1 fud.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}