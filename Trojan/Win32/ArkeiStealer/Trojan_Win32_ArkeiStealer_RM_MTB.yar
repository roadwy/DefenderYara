
rule Trojan_Win32_ArkeiStealer_RM_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e9 4c a6 b5 f2 e8 90 01 04 43 bb 44 c5 9a c3 31 32 89 c9 42 01 cb bb 26 05 bb 1f 39 fa 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_2{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8d 3c 03 e8 90 01 04 30 07 83 fd 19 75 90 02 14 ff 15 90 01 04 ff 74 24 90 01 01 56 56 ff 15 90 01 04 43 3b dd 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_3{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f2 33 ed 8b d9 57 8b fd 85 f6 7e 90 01 01 81 fe 85 02 00 00 75 90 01 01 55 55 55 55 55 55 ff 15 90 01 04 e8 90 01 04 30 04 1f 47 3b fe 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_4{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ff 3b d8 7e 90 01 01 56 eb 90 01 01 33 c0 81 fb 85 02 00 00 75 90 01 01 50 50 50 50 50 50 ff 15 90 01 04 8b 44 24 90 01 01 8d 34 07 e8 90 01 04 30 06 47 3b fb 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_5{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 90 01 04 56 33 f6 85 ff 7e 90 01 01 55 8b 2d 90 01 04 83 ff 90 01 01 75 90 01 01 6a 00 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 33 81 ff 91 05 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}