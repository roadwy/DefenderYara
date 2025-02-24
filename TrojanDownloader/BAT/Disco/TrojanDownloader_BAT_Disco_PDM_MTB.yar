
rule TrojanDownloader_BAT_Disco_PDM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Disco.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 1d 02 00 70 80 07 00 00 04 72 8d 02 00 70 80 08 00 00 04 2a } //3
		$a_01_1 = {00 06 07 06 07 91 7e 04 00 00 04 07 7e 04 00 00 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d d9 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}