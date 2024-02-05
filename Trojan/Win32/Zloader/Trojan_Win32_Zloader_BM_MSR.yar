
rule Trojan_Win32_Zloader_BM_MSR{
	meta:
		description = "Trojan:Win32/Zloader.BM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 69 72 63 6c 65 6f 70 70 6f 73 69 74 65 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 32 } //01 00 
		$a_01_2 = {63 3a 5c 46 6c 6f 77 65 72 53 70 72 69 6e 67 5c 4a 75 6d 70 45 76 65 6e 5c 54 68 72 6f 75 67 68 6f 62 73 65 72 76 65 5c 77 69 6c 6c 45 61 73 65 5c 45 79 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}