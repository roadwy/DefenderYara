
rule Trojan_BAT_CobaltStrike_MB_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 40 28 02 00 00 06 0b 06 16 07 06 8e 69 28 09 00 00 0a 07 d0 03 00 00 02 28 0a 00 00 0a 28 0b 00 00 0a 75 03 00 00 02 0c 08 6f 0c 00 00 06 26 de 0e 07 16 20 00 80 00 00 28 03 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_CobaltStrike_MB_MTB_2{
	meta:
		description = "Trojan:BAT/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 11 0a 9a 1f 10 28 ?? ?? ?? 0a 86 6f ?? ?? ?? 0a 00 11 0a 17 d6 13 0a 11 0a 11 09 31 df } //2
		$a_03_1 = {da 04 d6 1f 1a 5d 13 07 07 11 06 28 ?? ?? ?? 0a 11 07 d6 } //2
		$a_01_2 = {50 6f 6f 6c 41 6e 64 53 70 61 44 65 70 6f 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 PoolAndSpaDepot.My.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}