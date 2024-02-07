
rule Trojan_AndroidOS_HiddenAds_H{
	meta:
		description = "Trojan:AndroidOS/HiddenAds.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 6c 72 20 3d } //01 00  ulr =
		$a_01_1 = {46 49 4e 53 48 20 54 52 55 45 } //01 00  FINSH TRUE
		$a_01_2 = {48 61 76 65 20 53 49 4d 20 63 61 72 64 } //01 00  Have SIM card
		$a_01_3 = {75 6e 4d 75 74 65 54 72 61 63 6b 65 72 73 } //00 00  unMuteTrackers
	condition:
		any of ($a_*)
 
}