
rule Trojan_Win64_Latrodectus_GNS_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0e ?? 41 88 41 ?? 41 8d 42 ?? 41 83 c2 ?? 4c 63 c0 49 8b c7 49 f7 e0 48 c1 ea ?? 48 6b c2 ?? 4c 2b c0 4d 0f af c3 42 0f b6 44 04 28 43 32 44 0e fc 41 88 41 ff 49 ff cc 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}