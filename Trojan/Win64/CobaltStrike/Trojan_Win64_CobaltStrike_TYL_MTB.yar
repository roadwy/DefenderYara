
rule Trojan_Win64_CobaltStrike_TYL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 d2 43 8a 04 02 41 8d 49 90 01 01 41 30 03 49 8d 42 90 01 01 45 33 d2 41 83 f9 0b 4c 0f 45 d0 41 8b c1 45 33 c9 ff c3 49 ff c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}