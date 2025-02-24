
rule Trojan_Win64_CobaltStrike_WVY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 c2 88 55 77 30 c1 88 4d 76 31 c0 48 8d 0d a5 eb 01 00 48 63 14 08 81 74 95 e0 27 1e 00 00 48 83 c0 04 48 83 f8 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}