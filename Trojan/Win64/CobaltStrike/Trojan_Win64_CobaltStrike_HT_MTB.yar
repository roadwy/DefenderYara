
rule Trojan_Win64_CobaltStrike_HT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 6c 24 30 48 8d 0d f0 9c 01 00 89 6c 24 28 45 33 c9 45 33 c0 c7 44 24 20 04 00 00 00 ba 00 00 00 80 48 89 9c 24 70 04 00 00 ff 15 2b 1d 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}