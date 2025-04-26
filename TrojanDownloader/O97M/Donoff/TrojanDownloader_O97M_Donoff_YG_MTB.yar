
rule TrojanDownloader_O97M_Donoff_YG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.YG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 61 79 6c 6f 61 64 20 3d 20 22 78 78 78 24 36 39 3d 76 6e 6f 3f 73 7a 70 7e 7b 78 6d 72 61 7b 7a 7c 75 7d 77 78 6f 21 25 40 25 3d 2e 2c 6d 25 37 2f } //1 payload = "xxx$69=vno?szp~{xmra{z|u}wxo!%@%=.,m%7/
		$a_01_1 = {65 78 65 2e 72 65 70 70 6f 72 64 5f 6c 61 6e 72 65 74 65 2f 6d 6f 63 2e 78 65 77 72 65 62 79 63 2e 63 6e 63 2f 2f 3a 73 70 74 74 68 } //1 exe.reppord_lanrete/moc.xewrebyc.cnc//:sptth
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 28 22 32 76 6d 69 63 5c 74 6f 6f 72 5c 2e 5c 3a 73 74 6d 67 6d 6e 69 77 22 29 } //1 StrReverse("2vmic\toor\.\:stmgmniw")
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 28 22 70 75 74 72 61 74 53 73 73 65 63 6f 72 50 5f 32 33 6e 69 57 } //1 StrReverse("putratSssecorP_23niW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}