
rule TrojanDownloader_O97M_Obfuse_PAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 69 6f 6b 61 73 65 72 } //1 Niokaser
		$a_01_1 = {5c 4b 49 4f 4c 2e 46 45 52 52 41 41 53 53 } //1 \KIOL.FERRAASS
		$a_01_2 = {77 77 77 2e 63 6f 6d 70 75 70 6c 75 73 2e 69 6e 2f 6c 61 79 73 2f 72 65 73 68 79 2e 70 68 70 } //1 www.compuplus.in/lays/reshy.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}