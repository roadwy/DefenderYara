
rule Trojan_Win64_CobaltStrike_MBY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 48 89 7c 24 20 33 ff 4d 8d 59 ff 49 8b e8 48 8b da 48 8b f1 4c 3b } //2
		$a_01_1 = {dc 97 00 00 00 f0 00 00 00 98 00 00 00 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}