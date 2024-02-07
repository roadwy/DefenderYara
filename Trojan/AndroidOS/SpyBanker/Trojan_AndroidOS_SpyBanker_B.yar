
rule Trojan_AndroidOS_SpyBanker_B{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 61 63 74 69 76 69 64 61 64 65 73 3b } //02 00  /actividades;
		$a_01_1 = {75 6e 73 65 6e 74 4d 73 67 73 } //02 00  unsentMsgs
		$a_01_2 = {4c 63 6f 6d 2f 63 61 6e 6e 61 76 2f 63 75 61 73 69 6d 6f 64 6f 2f 6a 75 6d 70 65 72 2f 73 6f 6d 61 6c 69 61 3b } //00 00  Lcom/cannav/cuasimodo/jumper/somalia;
	condition:
		any of ($a_*)
 
}