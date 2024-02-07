
rule Trojan_Win32_Relbma_A{
	meta:
		description = "Trojan:Win32/Relbma.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {76 0c 80 b0 90 01 02 40 00 90 01 01 40 3b c6 72 f4 46 56 57 6a 03 90 00 } //01 00 
		$a_03_1 = {40 00 6a 66 e8 90 01 02 ff ff 68 90 01 02 40 00 6a 6a e8 90 01 02 ff ff 68 90 01 02 40 00 6a 69 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_2 = {76 09 80 34 38 90 01 01 40 3b c6 72 f7 8a 45 0f 53 6a 00 8d 90 00 } //01 00 
		$a_10_3 = {70 72 6f 74 65 63 74 2e 61 64 76 61 6e 63 65 64 63 6c 65 61 6e 65 72 2e 63 6f 6d } //01 00  protect.advancedcleaner.com
		$a_10_4 = {4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 47 75 61 72 64 22 20 62 69 6e 74 65 72 76 61 6c } //00 00  Microsoft Security Guard" binterval
	condition:
		any of ($a_*)
 
}