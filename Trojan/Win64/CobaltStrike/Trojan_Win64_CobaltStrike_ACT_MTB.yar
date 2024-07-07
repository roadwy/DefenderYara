
rule Trojan_Win64_CobaltStrike_ACT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 a3 fc 03 00 42 c6 85 a4 fc 03 00 42 c6 85 a5 fc 03 00 42 c6 85 a6 fc 03 00 42 c6 85 a7 fc 03 00 42 c6 85 a8 fc 03 00 42 c6 85 a9 fc 03 00 42 c6 85 aa fc 03 00 42 c6 85 ab fc 03 00 42 c6 85 ac fc 03 00 42 c6 85 ad fc 03 00 42 c6 85 ae fc 03 00 42 c6 85 af fc 03 00 42 c6 85 b0 fc 03 00 42 c6 85 b1 fc 03 00 42 c6 85 b2 fc 03 00 42 c6 85 b3 fc 03 00 42 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}