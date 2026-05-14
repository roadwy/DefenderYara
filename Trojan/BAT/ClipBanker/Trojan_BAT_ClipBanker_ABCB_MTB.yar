
rule Trojan_BAT_ClipBanker_ABCB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 94 03 61 d1 9d 07 17 58 0b 07 02 8e 69 32 ed } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}