
rule Trojan_Win64_IcedID_TA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c1 48 63 4c 24 ?? 66 3b ff } //1
		$a_03_1 = {0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 ?? e9 ?? ?? ?? ?? ff c0 99 66 3b f6 74 } //1
		$a_03_2 = {8b c2 89 44 24 ?? 3a f6 74 ?? f7 7c 24 ?? 8b c2 3a c9 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}