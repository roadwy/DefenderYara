
rule Trojan_Win32_Ursnif_RC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 40 8b 4c 24 2c 01 44 24 24 0f af c8 8b 44 24 24 2b c1 a3 } //01 00 
		$a_01_1 = {48 3a 5c 66 6c 6f 77 5c 72 65 70 72 6f 64 75 63 74 69 76 69 74 79 5c 61 63 74 5c 73 63 72 69 70 74 73 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d9 01 1d 90 01 04 8b 5c 24 90 01 01 33 c9 85 d2 0f 94 c1 85 c9 74 90 01 01 2b ca 90 00 } //01 00 
		$a_02_1 = {2b c8 03 f1 8b c8 2b ce 83 c1 90 01 01 8d 84 00 90 01 04 2b c1 03 c6 83 3d 90 01 05 89 0d 90 01 04 a3 90 01 04 75 90 01 01 8d 4e 90 01 01 03 f6 2b f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}