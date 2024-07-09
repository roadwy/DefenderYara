
rule Trojan_BAT_Seraph_GKH_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 08 16 1a 6f ?? ?? ?? 0a 26 08 16 28 ?? ?? ?? 0a 0d 07 16 73 0b 00 00 0a 13 04 09 8d 07 00 00 01 13 05 11 04 11 05 16 09 6f ?? ?? ?? 0a 26 11 05 13 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}