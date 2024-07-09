
rule Trojan_BAT_ClipBanker_NCA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 1e 00 00 0a 11 05 28 ?? 00 00 0a a5 ?? 00 00 02 28 ?? 00 00 0a 2b 0d 11 04 17 58 13 04 11 04 09 8e } //5
		$a_01_1 = {53 00 54 00 45 00 41 00 4d 00 20 00 54 00 52 00 41 00 44 00 45 00 20 00 4c 00 49 00 4e 00 4b 00 } //1 STEAM TRADE LINK
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}