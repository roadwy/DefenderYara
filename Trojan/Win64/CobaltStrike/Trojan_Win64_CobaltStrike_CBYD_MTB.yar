
rule Trojan_Win64_CobaltStrike_CBYD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CBYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 69 c8 ?? ?? ?? ?? 48 89 ca 48 c1 ea 3f 48 c1 e9 2d 01 d1 69 c9 ?? ?? ?? ?? 29 c8 30 03 48 8d 43 01 48 89 c3 48 39 f0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}