
rule Trojan_Win64_IcedID_MSD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 8c 24 ?? ?? ?? ?? eb 15 } //1
		$a_00_1 = {33 c8 8b c1 eb a6 } //1
		$a_03_2 = {48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9 } //1
		$a_00_3 = {88 04 0a e9 } //1
		$a_00_4 = {55 6e 73 61 64 6a 6b 62 61 73 66 } //1 Unsadjkbasf
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}