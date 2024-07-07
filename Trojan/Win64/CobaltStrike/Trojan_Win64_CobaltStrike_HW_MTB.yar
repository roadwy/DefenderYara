
rule Trojan_Win64_CobaltStrike_HW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 24 01 f6 d8 1a c9 ff c2 80 e1 f1 48 63 c2 80 c1 ea 41 30 08 49 ff c0 49 3b c1 72 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}