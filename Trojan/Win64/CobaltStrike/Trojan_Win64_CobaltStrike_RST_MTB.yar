
rule Trojan_Win64_CobaltStrike_RST_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RST!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c2 0f b6 d2 0f b6 9c 14 80 01 00 00 40 00 de 40 02 b4 14 80 00 00 00 40 0f b6 ee 0f b6 84 2c 80 01 00 00 88 84 14 80 01 00 00 88 9c 2c 80 01 00 00 02 9c 14 80 01 00 00 0f b6 c3 0f b6 84 04 80 01 00 00 41 30 04 3c 48 ff c7 49 39 fd 75 b0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}