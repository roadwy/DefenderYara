
rule Trojan_Win64_CobaltStrike_T_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 03 45 ?? ff 73 fc 50 8b 43 ?? 03 45 fc 50 ff 95 ?? ?? ?? ?? 0f b7 46 ?? 83 c4 ?? ff 45 e4 83 c3 ?? 39 45 e4 } //2
		$a_03_1 = {8b 45 f4 8a 00 88 45 ff 8a 01 0f be 7d ff 88 45 ?? 0f be c0 2b f8 ff 45 f4 80 7d ff } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}