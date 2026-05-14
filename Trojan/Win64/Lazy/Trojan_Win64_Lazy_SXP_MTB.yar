
rule Trojan_Win64_Lazy_SXP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 83 f8 2e ?? ?? 66 83 f8 3a ?? ?? 66 c7 01 5f 00 0f b7 41 02 48 83 c1 02 66 85 c0 } //10
		$a_80_1 = {25 73 69 6e 73 74 61 6c 6c 65 72 5f 6e 61 6d 65 2e 64 61 74 } //%sinstaller_name.dat  20
		$a_80_2 = {25 73 5c 73 65 63 6f 6e 64 61 72 79 5f 64 69 73 61 62 6c 65 64 2e 64 61 74 } //%s\secondary_disabled.dat  20
		$a_80_3 = {25 73 5c 63 6c 69 65 6e 74 5f 75 75 69 64 2e 64 61 74 } //%s\client_uuid.dat  5
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*20+(#a_80_2  & 1)*20+(#a_80_3  & 1)*5) >=55
 
}