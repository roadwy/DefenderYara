
rule Trojan_Win32_Tnega_MB_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 14 8b 44 24 08 56 8b 74 24 10 8a 16 32 d1 88 10 40 46 4f 75 } //1
		$a_01_1 = {53 6c 65 65 70 } //1 Sleep
		$a_01_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_3 = {44 65 6c 65 74 65 46 69 6c 65 41 } //1 DeleteFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}