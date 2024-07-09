
rule TrojanDropper_BAT_Klres_A_MTB{
	meta:
		description = "TrojanDropper:BAT/Klres.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 06 28 ?? 00 00 0a 3a ?? 00 00 00 06 28 ?? 00 00 0a 26 07 28 ?? 00 00 0a 39 ?? 00 00 00 ?? ?? ?? ?? ?? [0-05] 28 ?? 00 00 0a 13 04 16 13 05 38 ?? 00 00 00 11 04 11 05 9a 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 11 04 8e 69 3f e5 ff ff ff 08 28 ?? 00 00 0a 39 ?? 00 00 00 08 28 ?? 00 00 0a 08 04 28 ?? 00 00 0a 08 73 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}