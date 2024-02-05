
rule Trojan_AndroidOS_SAgnt_AH_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 48 61 6e 79 75 69 65 73 } //01 00 
		$a_01_1 = {64 65 63 72 79 70 74 } //01 00 
		$a_01_2 = {2f 42 65 72 6e 74 } //01 00 
		$a_01_3 = {6c 6f 61 64 65 64 41 70 6b 43 6c 61 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}