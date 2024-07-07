
rule Trojan_Win32_Ursnif_PA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 f8 0f af 41 90 01 01 89 41 90 01 01 a1 90 01 04 8b 1d 90 01 04 8b 0d 90 01 04 0f af da 8b 80 90 01 04 05 4e 0e 07 00 0f af 05 90 01 04 a3 90 01 04 a1 90 01 04 33 05 90 01 04 83 e8 3b 09 05 90 01 04 a1 90 01 04 88 1c 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 03 f6 2b f2 05 74 b3 b8 01 8b 54 24 18 81 c6 90 01 04 83 44 24 90 01 01 04 03 f1 89 44 24 14 a3 90 01 04 89 02 8b c6 2b 05 90 01 04 83 c0 06 ff 4c 24 90 01 01 0f b7 d0 89 54 24 90 01 01 0f 85 90 00 } //1
		$a_00_1 = {8b 44 24 18 8b 00 89 44 24 14 0f b7 c2 89 44 24 10 8b c6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}