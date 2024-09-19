
rule TrojanDownloader_BAT_Small_SGA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.SGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c } //4
		$a_00_1 = {70 00 72 00 30 00 74 00 30 00 74 00 79 00 70 00 33 00 } //1 pr0t0typ3
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}