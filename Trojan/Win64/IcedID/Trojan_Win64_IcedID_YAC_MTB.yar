
rule Trojan_Win64_IcedID_YAC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 17 48 03 c8 48 8b 44 24 ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}