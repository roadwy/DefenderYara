
rule Trojan_Win64_CobaltStrike_Q_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 45 88 48 8d 45 ?? 48 8b 4d ?? 45 33 c9 ba 10 66 00 00 48 89 44 24 20 ff 15 } //2
		$a_03_1 = {48 8d 44 24 ?? 48 89 44 24 ?? 45 33 c9 48 8d 45 ?? 45 33 c0 33 d2 48 89 44 24 20 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}