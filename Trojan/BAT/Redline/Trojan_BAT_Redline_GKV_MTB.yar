
rule Trojan_BAT_Redline_GKV_MTB{
	meta:
		description = "Trojan:BAT/Redline.GKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 7b 02 00 00 04 04 02 7b 02 00 00 04 6f 90 01 03 0a 5d 6f 90 01 03 0a 03 61 d2 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}