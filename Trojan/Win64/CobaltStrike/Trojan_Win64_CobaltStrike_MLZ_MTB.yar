
rule Trojan_Win64_CobaltStrike_MLZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c5 4c 33 c1 49 63 ca 49 f7 e0 41 ff c2 48 c1 ea 0a 48 69 c2 ?? ?? ?? ?? 33 d2 4c 2b c0 48 8b c1 4d 31 04 39 48 33 05 2e 59 0b 00 48 03 c1 48 f7 35 e4 58 0b 00 48 89 15 dd 58 0b 00 41 81 fa 04 19 00 00 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}