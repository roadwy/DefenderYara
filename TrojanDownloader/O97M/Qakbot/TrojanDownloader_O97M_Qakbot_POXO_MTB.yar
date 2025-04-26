
rule TrojanDownloader_O97M_Qakbot_POXO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.POXO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 73 69 6c 65 6e 74 20 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73 } //1 -silent ..\Popol.gors
		$a_01_1 = {2d 73 69 6c 65 6e 74 20 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73 31 } //1 -silent ..\Popol.gors1
		$a_01_2 = {2d 73 69 6c 65 6e 74 20 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73 32 } //1 -silent ..\Popol.gors2
		$a_01_3 = {50 6f 70 6f 6c 2e 6f 63 78 } //1 Popol.ocx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}