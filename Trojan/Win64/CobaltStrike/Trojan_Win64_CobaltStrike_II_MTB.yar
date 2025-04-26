
rule Trojan_Win64_CobaltStrike_II_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.II!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 ?? 8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_II_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.II!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c3 48 8b 54 24 20 88 04 0a eb df eb ef 89 04 24 8b 44 24 28 eb db 48 83 ec 18 c7 04 24 00 00 00 00 eb ed eb c5 48 8b 4c 24 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}