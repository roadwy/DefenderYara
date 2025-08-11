
rule Trojan_Win64_Donut_ZID_MTB{
	meta:
		description = "Trojan:Win64/Donut.ZID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 2b c2 41 8b cf 41 2b c9 0f 1f 40 00 42 0f b6 04 02 30 02 48 8d 52 01 48 83 e9 01 75 ef 4d 63 c7 48 8b d7 48 8d 8c 24 ?? ?? ?? ?? e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}