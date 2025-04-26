
rule Trojan_Win64_CobaltStrike_RFAK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RFAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 c8 48 8d 54 24 70 48 03 d1 0f b6 0a 41 88 0a 44 88 1a 41 0f b6 12 49 03 d3 0f b6 ca 0f b6 54 0c 70 41 30 11 49 ff c1 48 83 eb 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}