
rule Trojan_Win32_Disstl_DD_MTB{
	meta:
		description = "Trojan:Win32/Disstl.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {79 7c 77 3b 69 65 76 37 36 32 68 70 70 } //y|w;iev762hpp  03 00 
		$a_80_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  03 00 
		$a_80_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //GetProcAddress  03 00 
		$a_80_3 = {77 77 77 2e 63 72 79 70 74 65 72 } //www.crypter  03 00 
		$a_80_4 = {50 68 73 39 65 6f 68 57 78 76 6d 72 6b 45 } //Phs9eohWxvmrkE  03 00 
		$a_80_5 = {57 74 58 35 45 6e 58 4d 47 } //WtX5EnXMG  03 00 
		$a_80_6 = {47 65 74 4c 6f 6e 67 50 61 74 68 4e 61 6d 65 41 } //GetLongPathNameA  00 00 
	condition:
		any of ($a_*)
 
}