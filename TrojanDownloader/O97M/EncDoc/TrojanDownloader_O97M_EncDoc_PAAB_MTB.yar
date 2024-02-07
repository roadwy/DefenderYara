
rule TrojanDownloader_O97M_EncDoc_PAAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6e 74 65 6e 74 2e 66 69 6e 64 2e 65 78 65 63 75 74 65 66 69 6e 64 74 65 78 74 3a 3d 22 33 2d 22 2c 72 65 70 6c 61 63 65 77 69 74 68 3a 3d 22 22 2c 72 65 70 6c 61 63 65 3a 3d 32 } //01 00  .content.find.executefindtext:="3-",replacewith:="",replace:=2
		$a_01_1 = {63 66 75 6e 63 74 69 6f 6e 73 28 6e 65 78 74 64 6f 6f 72 6b 61 72 6f 6c 2c 6c 69 6b 65 74 75 62 65 6c 6f 61 64 29 63 } //01 00  cfunctions(nextdoorkarol,liketubeload)c
		$a_01_2 = {65 73 28 22 63 61 74 65 67 6f 72 79 22 29 2e 76 61 6c 75 65 29 2e 65 78 65 63 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 22 2b 6c } //00 00  es("category").value).exec"c:\windows\explorer"+l
	condition:
		any of ($a_*)
 
}