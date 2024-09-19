
rule Trojan_Win64_CobaltStrike_CCJD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b cc ba 10 dc 47 00 33 c9 41 b8 00 30 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 b9 d0 07 00 00 ff 15 ?? ?? ?? ?? 41 b8 90 90 57 29 00 48 8d 15 ?? ?? ?? ?? 48 8b cf e8 ?? ?? ?? ?? 4c 8d 4c 24 20 ba 10 dc 47 00 41 b8 40 00 00 00 48 8b cf ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}