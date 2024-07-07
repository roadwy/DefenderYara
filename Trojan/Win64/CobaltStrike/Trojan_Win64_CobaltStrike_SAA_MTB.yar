
rule Trojan_Win64_CobaltStrike_SAA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca 81 e1 90 01 04 7d 90 01 01 ff c9 83 c9 90 01 01 ff c1 48 90 01 02 48 90 01 03 0f b6 8c 31 90 01 04 41 90 01 03 41 90 01 03 ff c2 49 90 01 02 3b 55 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}