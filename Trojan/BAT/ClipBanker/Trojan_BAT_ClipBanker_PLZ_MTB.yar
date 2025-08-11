
rule Trojan_BAT_ClipBanker_PLZ_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 fe 0e 00 00 fe 09 00 00 6f ?? 00 00 0a 8d 3f 00 00 01 fe 0e 01 00 20 00 00 00 00 fe 0e 02 00 20 00 00 00 00 fe 0e 03 00 38 50 00 00 00 fe 0c 01 00 fe 0c 03 00 fe 09 00 00 fe 0c 03 00 6f ?? 00 00 0a fe 0c 00 00 fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 9c fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 fe 0c 03 00 20 01 00 00 00 58 fe 0e 03 00 fe 0c 03 00 fe 09 00 00 6f ?? 00 00 0a 3f 9e } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}