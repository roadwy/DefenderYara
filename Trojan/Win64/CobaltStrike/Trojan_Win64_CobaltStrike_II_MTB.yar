
rule Trojan_Win64_CobaltStrike_II_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.II!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c3 48 8b 54 24 20 88 04 0a eb df eb ef 89 04 24 8b 44 24 28 eb db 48 83 ec 18 c7 04 24 00 00 00 00 eb ed eb c5 48 8b 4c 24 30 } //00 00 
	condition:
		any of ($a_*)
 
}