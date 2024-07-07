
rule Trojan_Win64_CobaltStrike_WN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 4d 8d 5b 01 48 f7 f5 ff c7 42 0f b6 04 32 42 32 44 1e ff 41 88 43 ff 48 63 c7 48 3b c3 72 df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}