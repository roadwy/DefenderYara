
rule Trojan_BAT_Redlinestealer_ZEH_MTB{
	meta:
		description = "Trojan:BAT/Redlinestealer.ZEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 1f 10 ?? cd 00 00 0a 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? 3d 01 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 7d ?? 00 00 04 06 16 1f 20 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}