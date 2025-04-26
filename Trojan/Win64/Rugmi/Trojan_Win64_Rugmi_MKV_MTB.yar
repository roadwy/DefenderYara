
rule Trojan_Win64_Rugmi_MKV_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb 41 33 da 41 2b da 89 d9 41 0f af c9 81 c1 80 00 00 00 c1 e9 08 81 f1 00 00 80 00 81 e9 00 00 80 00 8b d9 48 0f b6 4c ?? ?? d3 e3 2b 1a 89 1a 48 83 c2 04 48 83 c0 04 41 83 c0 01 45 3b c3 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}