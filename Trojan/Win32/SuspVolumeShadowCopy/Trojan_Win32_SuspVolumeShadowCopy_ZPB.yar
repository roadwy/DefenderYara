
rule Trojan_Win32_SuspVolumeShadowCopy_ZPB{
	meta:
		description = "Trojan:Win32/SuspVolumeShadowCopy.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {64 00 69 00 73 00 6b 00 73 00 68 00 61 00 64 00 6f 00 77 00 90 00 02 00 0a 00 20 00 2f 00 73 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SuspVolumeShadowCopy_ZPB_2{
	meta:
		description = "Trojan:Win32/SuspVolumeShadowCopy.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 } //1 wmic
		$a_00_1 = {73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //1 shadowcopy
		$a_00_2 = {63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 3d 00 } //1 call create Volume=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_SuspVolumeShadowCopy_ZPB_3{
	meta:
		description = "Trojan:Win32/SuspVolumeShadowCopy.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 } //1 mklink
		$a_00_1 = {20 00 2f 00 44 00 20 00 } //1  /D 
		$a_00_2 = {5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 \GLOBALROOT\Device\HarddiskVolumeShadowCopy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}