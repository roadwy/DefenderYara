
rule Trojan_BAT_CrysomeLoader_SX_MTB{
	meta:
		description = "Trojan:BAT/CrysomeLoader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 2d 07 72 ?? ?? 00 70 2b 15 02 7b ?? 00 00 04 6f ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 06 2d 03 } //20
		$a_80_1 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 22 43 72 79 73 6f 6d 65 4c 6f 61 64 65 72 22 20 2f 74 72 20 22 } ///create /tn "CrysomeLoader" /tr "  10
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*10) >=30
 
}