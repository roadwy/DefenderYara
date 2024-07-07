
rule Trojan_Win64_CobaltStrike_P_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 74 3c 70 58 48 8d 0d 14 23 00 00 0f b6 54 3c 70 e8 90 01 04 48 ff c7 48 81 ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}