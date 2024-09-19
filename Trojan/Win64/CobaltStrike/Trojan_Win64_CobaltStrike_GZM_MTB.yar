
rule Trojan_Win64_CobaltStrike_GZM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b d6 48 8b cb e8 ?? ?? ?? ?? b9 33 23 33 23 ff 15 ?? ?? ?? ?? ?? 48 8b 54 24 68 48 83 fa 0f } //5
		$a_01_1 = {48 8b 04 25 60 00 00 00 45 33 c0 48 8b 50 18 4c 8b 52 10 49 8b 42 30 48 85 c0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}