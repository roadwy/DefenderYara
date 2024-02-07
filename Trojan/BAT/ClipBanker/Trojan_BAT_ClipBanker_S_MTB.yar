
rule Trojan_BAT_ClipBanker_S_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 e6 00 00 00 40 00 00 00 8d 01 00 00 da 03 } //01 00 
		$a_01_1 = {52 74 6c 53 65 74 50 72 6f 63 65 73 73 49 73 43 72 69 74 69 63 61 6c } //01 00  RtlSetProcessIsCritical
		$a_01_2 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //00 00  GetTempFileName
	condition:
		any of ($a_*)
 
}