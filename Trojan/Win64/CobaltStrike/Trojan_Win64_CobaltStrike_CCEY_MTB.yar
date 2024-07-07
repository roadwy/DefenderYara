
rule Trojan_Win64_CobaltStrike_CCEY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 48 48 8d 44 24 30 45 33 c9 48 89 44 24 28 33 d2 48 89 5c 24 20 45 8d 41 01 ff 15 } //1
		$a_01_1 = {48 8d be 08 01 00 00 48 89 7c 24 30 8b 56 50 41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 4e 30 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}