
rule Trojan_BAT_ClipBanker_ACL_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 dc 05 00 00 28 ?? 00 00 0a 17 72 ?? 13 00 70 12 00 73 ?? 00 00 0a 80 ?? 00 00 04 06 2d 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_ClipBanker_ACL_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 13 07 06 72 03 01 00 70 15 16 28 ?? ?? ?? 0a 0b 1e 13 07 19 09 07 19 9a 28 ?? ?? ?? 0a 1f 20 19 15 15 28 ?? ?? ?? 0a 00 1f 09 13 07 19 07 17 9a 15 6a 16 28 ?? ?? ?? 0a 00 1f 0a 13 07 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_ClipBanker_ACL_MTB_3{
	meta:
		description = "Trojan:BAT/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 1f 64 28 28 00 00 0a 28 27 00 00 0a 07 28 29 00 00 0a 0c 12 02 28 } //1
		$a_03_1 = {72 db 00 00 70 6f ?? 00 00 0a 25 72 eb 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}