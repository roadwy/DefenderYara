
rule Trojan_BAT_ClipBanker_ARS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 2b 0e 08 17 58 0c 08 7e ?? ?? ?? ?? 8e 69 32 cd } //15
		$a_03_1 = {dc 07 25 6f ?? ?? ?? ?? 13 05 11 05 17 59 } //5
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}