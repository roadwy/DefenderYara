
rule Trojan_Win32_ArkeiStealer_RM_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e9 4c a6 b5 f2 e8 ?? ?? ?? ?? 43 bb 44 c5 9a c3 31 32 89 c9 42 01 cb bb 26 05 bb 1f 39 fa 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_2{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8d 3c 03 e8 ?? ?? ?? ?? 30 07 83 fd 19 75 [0-14] ff 15 ?? ?? ?? ?? ff 74 24 ?? 56 56 ff 15 ?? ?? ?? ?? 43 3b dd 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_3{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f2 33 ed 8b d9 57 8b fd 85 f6 7e ?? 81 fe 85 02 00 00 75 ?? 55 55 55 55 55 55 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1f 47 3b fe 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_4{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ff 3b d8 7e ?? 56 eb ?? 33 c0 81 fb 85 02 00 00 75 ?? 50 50 50 50 50 50 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b fb 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ArkeiStealer_RM_MTB_5{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 83 ff ?? 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 81 ff 91 05 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}