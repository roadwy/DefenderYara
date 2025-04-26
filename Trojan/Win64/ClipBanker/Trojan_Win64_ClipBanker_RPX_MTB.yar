
rule Trojan_Win64_ClipBanker_RPX_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 a2 48 63 c3 0f b6 0c 30 0f b6 c1 34 65 02 c1 88 45 a3 8d 53 02 48 63 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}