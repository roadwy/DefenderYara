
rule TrojanDownloader_BAT_AsyncRAT_CG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 ff b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 af 02 00 00 cd 02 00 00 4d 08 00 00 1f 31 } //02 00 
		$a_01_1 = {50 72 65 64 69 63 61 74 65 52 6f 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}