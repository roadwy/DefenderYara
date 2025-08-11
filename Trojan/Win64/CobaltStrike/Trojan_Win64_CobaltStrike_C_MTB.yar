
rule Trojan_Win64_CobaltStrike_C_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 b9 00 00 00 00 ff d0 49 89 ?? 48 8d 15 ?? ?? ?? ?? b9 06 00 00 00 b8 00 00 00 00 48 89 d7 f3 48 ab } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_C_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 55 fc 48 8d 05 8d 1b 00 00 49 89 d1 41 b8 40 00 00 00 ba 4e 88 05 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 } //3
		$a_01_1 = {48 83 ec 30 48 89 4d 10 48 8b 45 10 48 89 45 f8 48 8b 45 f8 ff d0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}