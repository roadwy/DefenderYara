
rule TrojanDownloader_O97M_Obfuse_NZM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NZM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 20 68 22 } //01 00  = "m" + "s" + "h" + "t" + "a h"
		$a_01_1 = {3d 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 } //01 00  = "t" + "t" + "p" + ":" + "/" + "/" + "w" + "w" + "w"
		$a_01_2 = {3d 20 22 2e 6a 2e 6d 70 2f 64 64 73 6f 62 75 6e 62 63 68 6f 6e 74 65 73 6b 61 74 65 65 73 6a 64 77 22 } //01 00  = ".j.mp/ddsobunbchonteskateesjdw"
		$a_01_3 = {2e 63 6f 6d 70 75 74 65 72 32 20 2b 20 63 61 6c 63 20 5f } //00 00  .computer2 + calc _
	condition:
		any of ($a_*)
 
}