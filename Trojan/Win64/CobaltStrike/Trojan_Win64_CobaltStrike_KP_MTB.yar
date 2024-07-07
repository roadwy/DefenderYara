
rule Trojan_Win64_CobaltStrike_KP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 88 1c 30 4b 8d 0c 37 48 ff c1 49 ff c6 4c 89 74 24 90 01 01 4c 39 e1 74 90 00 } //1
		$a_03_1 = {48 89 e9 48 ff c5 48 39 fd 48 0f 43 ee 43 0f b6 1c 37 41 32 5c 0d 90 01 01 4c 3b 74 24 90 01 01 75 ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}