
rule Trojan_Win32_NanoCore_VD_MTB{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 34 01 17 41 81 f9 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NanoCore_VD_MTB_2{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 d2 81 c2 90 01 04 80 34 01 90 01 01 41 39 d1 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NanoCore_VD_MTB_3{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 45 fc 41 39 d1 75 90 09 0b 00 c7 45 fc 90 01 04 80 34 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NanoCore_VD_MTB_4{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c0 41 89 90 02 40 39 d9 90 02 40 90 13 80 34 01 90 00 } //01 00 
		$a_03_1 = {89 c0 41 89 90 02 40 39 d9 90 02 40 90 13 89 90 02 40 80 34 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NanoCore_VD_MTB_5{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f6 85 d2 90 02 40 8b c3 03 c1 90 02 40 80 30 90 02 40 41 90 00 } //01 00 
		$a_03_1 = {33 d2 f7 f3 85 d2 90 02 40 8b c6 03 c1 90 02 40 b2 90 02 40 30 10 90 02 40 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}