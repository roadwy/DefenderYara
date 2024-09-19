
rule Trojan_BAT_ClipBanker_GNK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 16 2d ea 17 58 0d 09 06 8e 69 32 e4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}