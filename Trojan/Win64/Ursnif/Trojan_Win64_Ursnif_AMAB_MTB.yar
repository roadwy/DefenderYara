
rule Trojan_Win64_Ursnif_AMAB_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b ca 83 7c 24 28 00 8b 04 11 44 8b c8 74 90 01 01 85 c0 75 90 01 01 44 8d 40 01 eb 90 01 01 45 2b d3 41 03 c2 45 8b d1 89 02 48 83 c2 04 41 83 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}