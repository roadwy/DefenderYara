
rule Trojan_AndroidOS_SAgnt_AL_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 6c 69 76 65 72 50 49 31 } //01 00  deliverPI1
		$a_01_1 = {73 65 6e 74 42 52 31 } //01 00  sentBR1
		$a_01_2 = {6d 65 73 73 65 6e 67 6e 75 6d 6d 32 32 } //01 00  messengnumm22
		$a_01_3 = {41 75 74 6f 53 74 61 72 74 } //00 00  AutoStart
	condition:
		any of ($a_*)
 
}