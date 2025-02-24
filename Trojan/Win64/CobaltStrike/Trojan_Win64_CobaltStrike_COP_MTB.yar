
rule Trojan_Win64_CobaltStrike_COP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.COP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 48 c1 e1 06 48 8d 15 b6 e9 2d 00 48 8d 0c 0a 48 8d 49 08 48 ff c0 44 0f 11 39 48 83 f8 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}