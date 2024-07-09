
rule Trojan_Win64_Convagent_DS_MTB{
	meta:
		description = "Trojan:Win64/Convagent.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 7c 24 28 44 89 7c 24 20 45 33 c9 4d 8b c6 33 d2 33 c9 ff 15 [0-04] 48 8b d8 48 85 c0 0f 84 [0-04] ba ff ff ff ff 48 8b c8 ff 15 [0-04] 48 8b cb ff 15 } //1
		$a_03_1 = {48 8b 7d c8 48 2b df 48 c1 fb 03 41 b9 40 00 00 00 41 b8 00 10 00 00 48 8b d3 33 c9 ff 15 [0-04] 4c 8b f0 48 85 c0 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}