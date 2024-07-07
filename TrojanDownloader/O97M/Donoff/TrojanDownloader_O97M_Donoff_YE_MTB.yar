
rule TrojanDownloader_O97M_Donoff_YE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.YE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 78 61 73 90 02 16 73 6f 64 6b 61 6f 73 90 00 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 90 02 20 6f 73 90 00 } //1
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 63 61 6c 63 34 } //1 Function calc4
		$a_00_3 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 6c 75 6c 6c 69 } //1 createobject("wscript.shell").execlulli
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}