
rule Trojan_Win64_IcedID_LEH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.LEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 8b 4c 24 ?? 66 3b c9 74 ?? 48 8b 4c 24 ?? 48 03 c8 3a c9 74 ?? 48 89 44 24 ?? c7 44 24 20 ?? ?? ?? ?? e9 } //1
		$a_03_1 = {48 8b 54 24 ?? 4c 8b 84 24 ?? ?? ?? ?? 66 3b f6 74 ?? 48 8b c1 48 89 44 24 ?? 66 3b ed 74 ?? 41 8a 04 00 88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}