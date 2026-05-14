
rule Trojan_BAT_ClipBanker_VD_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 7f 00 00 0a 72 32 04 00 70 17 6f 80 00 00 0a 0a 06 72 18 04 00 70 03 6f 81 00 00 0a 00 06 6f 82 00 00 0a 00 de 0d } //5
		$a_81_1 = {65 36 65 63 62 64 32 34 2d 31 35 30 37 2d 34 33 34 62 2d 39 31 35 39 2d 30 37 61 63 62 38 34 61 35 35 32 33 } //1 e6ecbd24-1507-434b-9159-07acb84a5523
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}