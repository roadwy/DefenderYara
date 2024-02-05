
rule TrojanDownloader_BAT_Fsysna_SL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Fsysna.SL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 07 11 05 07 8e 69 5d 91 09 11 05 91 61 d2 9c 11 05 17 58 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}