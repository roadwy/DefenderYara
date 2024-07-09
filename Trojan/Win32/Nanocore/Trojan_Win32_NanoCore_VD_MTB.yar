
rule Trojan_Win32_NanoCore_VD_MTB{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 34 01 17 41 81 f9 ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NanoCore_VD_MTB_2{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 81 c2 ?? ?? ?? ?? 80 34 01 ?? 41 39 d1 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NanoCore_VD_MTB_3{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 45 fc 41 39 d1 75 90 09 0b 00 c7 45 fc ?? ?? ?? ?? 80 34 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NanoCore_VD_MTB_4{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c0 41 89 [0-40] 39 d9 [0-40] 90 13 80 34 01 } //1
		$a_03_1 = {89 c0 41 89 [0-40] 39 d9 [0-40] 90 13 89 [0-40] 80 34 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_NanoCore_VD_MTB_5{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f6 85 d2 [0-40] 8b c3 03 c1 [0-40] 80 30 [0-40] 41 } //1
		$a_03_1 = {33 d2 f7 f3 85 d2 [0-40] 8b c6 03 c1 [0-40] b2 [0-40] 30 10 [0-40] 41 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}