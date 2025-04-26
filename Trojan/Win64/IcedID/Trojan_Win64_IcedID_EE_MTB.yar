
rule Trojan_Win64_IcedID_EE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 48 8b 44 24 ?? 42 0f b6 8c 39 ?? ?? ?? ?? 41 32 4c 00 ?? 43 88 4c 08 ?? 3b 5c 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}