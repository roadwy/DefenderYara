
rule Trojan_BAT_ClipBanker_A_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 40 00 00 0a 03 07 03 6f 48 00 00 0a 5d 6f 40 00 00 0a 61 d1 6f 49 00 00 0a 26 07 17 58 0b 07 02 6f 48 00 00 0a 32 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}