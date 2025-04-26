
rule Trojan_Win64_IcedID_TS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 48 63 4c 24 ?? eb } //1
		$a_00_1 = {0f b6 8c 0c c0 00 00 00 33 c1 e9 } //1
		$a_03_2 = {48 63 4c 24 1c 48 8b 94 24 ?? ?? ?? ?? e9 } //1
		$a_00_3 = {88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}