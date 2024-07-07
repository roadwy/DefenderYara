
rule TrojanDownloader_BAT_Tiny_MVF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.MVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 0f 00 00 70 28 04 00 00 06 0b 07 28 08 00 00 06 } //1
		$a_00_1 = {53 6c 69 76 65 72 5f 73 74 61 67 65 72 2e 65 78 65 } //1 Sliver_stager.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}