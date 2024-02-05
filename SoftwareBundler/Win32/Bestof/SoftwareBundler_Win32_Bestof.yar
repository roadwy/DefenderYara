
rule SoftwareBundler_Win32_Bestof{
	meta:
		description = "SoftwareBundler:Win32/Bestof,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 61 63 5f 74 6f 62 6d 5f 70 75 74 65 73 } //02 00 
		$a_01_1 = {65 7a 69 74 65 6e 6f 6d 61 2f 6f 67 73 61 72 74 } //02 00 
		$a_01_2 = {6d 6f 63 2e 73 75 74 61 69 63 73 61 66 73 75 69 62 6f 63 65 6d 72 79 6d } //01 00 
		$a_01_3 = {2f 2f 56 45 52 59 53 49 4c 45 4e 54 } //01 00 
		$a_01_4 = {7b 74 6d 70 7d 5c 69 6e 73 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}