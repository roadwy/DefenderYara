
rule Trojan_Win64_CobaltStrike_ASJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 df 48 89 ce 48 8b 5c 24 ?? 48 89 c1 48 8b 44 24 ?? e8 ?? ?? ?? ?? 48 89 44 24 48 48 89 5c 24 58 48 8b 4c 24 38 48 8d ?? ?? ?? ?? 00 48 89 cb e8 ?? ?? ?? ?? 48 89 44 24 } //4
		$a_01_1 = {6d 61 69 6e 2e 41 65 73 44 65 63 72 79 70 74 } //1 main.AesDecrypt
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
rule Trojan_Win64_CobaltStrike_ASJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 54 24 38 99 41 f7 f8 48 63 d2 0f b6 04 16 41 32 04 09 41 88 04 0a 48 8b 35 6f 1b 00 00 0f b6 04 16 41 88 04 09 48 83 c1 01 39 0d 65 1b 00 00 77 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}