
rule Trojan_Win32_Lazy_CP_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 70 76 62 7a 71 63 73 2e 64 6c 6c 00 6e 79 6b 73 72 62 77 00 6d 6a 73 75 71 72 6b 00 79 6d 6f 71 78 6c 75 72 61 70 69 6b } //01 00 
		$a_01_1 = {69 68 65 74 61 71 6e 6d 2e 64 6c 6c 00 66 74 69 6a 77 78 00 65 6f 69 6e 6a 77 62 00 64 69 71 77 73 70 63 72 } //01 00 
		$a_01_2 = {6e 70 76 66 78 74 73 7a 2e 64 6c 6c 00 6b 66 71 79 78 62 6e 00 6b 79 6e 6d 78 69 76 73 65 66 71 00 67 61 73 62 65 69 72 68 6e 76 64 } //01 00 
		$a_01_3 = {6a 6e 67 78 61 7a 69 6c 2e 64 6c 6c 00 6f 71 6d 67 66 73 61 6a 77 62 00 61 6d 72 77 6e 64 66 7a 74 78 00 68 67 7a 71 73 6b 74 } //01 00 
		$a_01_4 = {7a 61 64 76 6d 65 67 74 2e 64 6c 6c 00 75 71 6f 6a 63 65 79 78 64 00 6e 6a 61 75 71 67 63 76 69 72 00 6f 62 6a 70 7a 71 6d 77 79 } //01 00 
		$a_01_5 = {6b 65 6d 61 76 77 62 75 2e 64 6c 6c 00 67 66 71 74 6d 6a 6e 6b 00 72 77 64 67 73 63 70 69 78 79 00 71 6f 66 75 64 62 } //01 00 
		$a_01_6 = {77 72 6d 71 76 79 6a 67 2e 64 6c 6c 00 6d 76 6b 77 63 73 6c 61 6a 68 66 00 68 74 79 73 72 78 7a 70 67 00 69 63 76 6d 70 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lazy_CP_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {7a 6b 71 68 70 6d 72 6e 2e 64 6c 6c 00 79 6c 69 64 76 6f 00 66 69 6b 62 72 74 7a 6d 00 7a 76 77 73 71 74 63 6e 70 67 65 6f 00 6b 6e 79 68 76 6a 6c 66 69 00 71 7a 75 68 67 6a 74 6c 63 73 } //04 00 
		$a_01_1 = {72 78 64 61 7a 77 71 6f 2e 64 6c 6c 00 73 79 6c 72 76 66 64 00 6c 67 6b 78 7a 6f 62 71 75 64 76 00 70 79 74 78 6c 61 67 77 72 62 6b 65 00 63 62 65 70 66 79 64 61 67 6e 6d 76 00 6f 61 64 67 69 6e 63 71 62 6c } //04 00 
		$a_01_2 = {79 66 6b 63 65 73 68 6e 2e 64 6c 6c 00 67 74 65 73 68 63 66 77 72 00 78 79 6f 72 62 6c 64 77 00 6b 6f 74 78 67 70 62 66 73 6e 77 } //04 00 
		$a_01_3 = {6e 76 6b 61 6c 67 75 72 2e 64 6c 6c 00 6b 73 61 65 69 78 6a 6d 00 71 7a 6b 63 72 76 74 00 68 79 74 73 62 78 63 76 00 67 65 74 7a 75 73 68 66 71 69 62 6e 00 66 79 73 6f 74 6c 62 78 75 65 } //04 00 
		$a_01_4 = {6e 63 6f 76 6b 65 72 70 2e 64 6c 6c 00 72 6b 62 66 77 6e 00 64 66 68 72 6b 67 6f 75 00 63 77 70 62 68 6a 00 76 79 7a 6c 65 66 61 64 00 64 62 61 79 76 74 } //04 00 
		$a_01_5 = {62 7a 75 73 74 79 6f 6a 2e 64 6c 6c 00 6a 77 79 6e 78 70 6c 00 79 64 65 74 6b 6d 6c 62 75 00 65 76 79 63 73 61 6c 6a 6b 00 62 68 71 78 75 6f 00 73 70 68 66 6a 78 74 6d 6f } //04 00 
		$a_01_6 = {72 6f 71 77 65 73 64 67 2e 64 6c 6c 00 62 70 78 67 73 76 77 00 79 61 69 6f 67 71 77 73 68 6e 00 7a 68 73 61 6b 79 78 71 69 00 72 6d 71 70 78 6a 69 64 76 00 6d 75 79 65 67 70 6c } //00 00 
	condition:
		any of ($a_*)
 
}