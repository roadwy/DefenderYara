
rule Trojan_Win64_ClipBanker_ACL_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 38 48 8d 44 24 30 48 8d 15 06 9d 01 00 44 8b cb 45 33 c0 89 5c 24 28 48 89 44 24 20 ff 15 ?? ?? ?? ?? 48 8b 4c 24 38 ff 15 ?? ?? ?? ?? b9 50 c3 00 00 ff 15 } //3
		$a_03_1 = {40 53 48 83 ec 40 4c 8d 05 33 9d 01 00 ba 01 00 00 00 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}