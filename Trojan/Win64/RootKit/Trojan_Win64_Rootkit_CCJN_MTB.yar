
rule Trojan_Win64_Rootkit_CCJN_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 64 24 40 00 48 8d 54 24 40 48 8b c8 ff 15 ?? ?? ?? ?? 8b f8 85 c0 78 ?? 8b 4b 04 48 83 64 24 48 00 48 89 4c 24 50 48 8b 4c 24 40 ff 15 ?? ?? ?? ?? 8b 4b 08 4c 8d 4c 24 50 89 4c 24 28 48 8d 54 24 48 48 83 c9 ff c7 44 24 20 00 30 00 00 45 33 c0 ff 15 ?? ?? ?? ?? ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}