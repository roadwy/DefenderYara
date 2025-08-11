
rule Trojan_BAT_ClipBanker_SL_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 16 7e 05 00 00 04 12 00 73 1c 00 00 0a 26 06 2d 06 17 28 1d 00 00 0a 2a } //2
		$a_81_1 = {70 72 65 64 73 74 30 31 34 } //2 predst014
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}