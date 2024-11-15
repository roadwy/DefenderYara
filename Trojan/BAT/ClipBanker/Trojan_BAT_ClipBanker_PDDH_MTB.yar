
rule Trojan_BAT_ClipBanker_PDDH_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PDDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 60 61 20 11 88 ba 4c 61 16 33 02 2b 36 1f 1e 06 1f 21 5a 06 1f 1f 5a 58 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}