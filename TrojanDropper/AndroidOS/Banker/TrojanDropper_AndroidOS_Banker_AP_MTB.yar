
rule TrojanDropper_AndroidOS_Banker_AP_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AP!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 12 2f 00 14 09 bb 4a 96 00 b0 94 48 09 03 02 14 0a 39 ea 6d 00 91 0a 04 0a dc 0b 02 03 48 0b 08 0b 14 0c d0 e6 06 00 92 0c 0c 0a b1 4c da 0a 0a 00 b3 4a b0 0a b0 9a 93 09 0c 0c d8 09 09 ff b0 9a 94 09 0c 0c b0 9a 97 09 0a 0b 8d 99 4f 09 06 02 93 04 07 04 d8 02 02 01 01 c4 28 d2 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}