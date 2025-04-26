
rule Trojan_Win64_IcedID_FYI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 bc 24 18 ?? ?? ?? 8b c2 eb ?? 33 c8 8b c1 eb ?? 48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9 9b } //5
		$a_03_1 = {ff c0 89 04 ?? eb 24 80 44 24 4a ?? c6 44 24 4b ?? eb ?? 80 44 24 50 ?? c6 44 24 51 ?? eb ?? 80 44 24 4f ?? c6 44 24 50 ?? eb } //5
		$a_01_2 = {48 62 61 73 68 66 6b 6a 61 73 } //1 Hbashfkjas
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}