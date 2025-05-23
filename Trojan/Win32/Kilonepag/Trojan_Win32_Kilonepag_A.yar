
rule Trojan_Win32_Kilonepag_A{
	meta:
		description = "Trojan:Win32/Kilonepag.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {51 51 44 6f 63 74 6f 72 52 74 70 2e 65 78 65 00 52 61 76 2e 65 78 65 00 77 78 43 6c 74 41 69 64 2e 65 78 65 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 33 33 32 32 2e 6f 72 67 2f 64 79 6e 64 6e 73 2f 67 65 74 69 70 [0-04] 26 63 3d [0-04] 26 62 3d [0-04] 68 74 74 70 3a 2f 2f [0-1f] 2e 61 73 70 } //1
		$a_02_2 = {68 74 74 70 3a 2f 2f 25 [0-20] 25 32 45 25 36 33 25 36 46 25 36 44 2f [0-02] 2e 65 78 65 [0-08] (51 51 47 61 6d 65|73 76 63 68 6f 73 74) 2e 65 78 65 } //1
		$a_02_3 = {64 65 6c 20 2a 2a 2a 2a 2a 2a 2a 2a 0d 0a 64 65 6c 20 25 30 00 2a 2a 2a 2a 2a 2a 2a 2a 00 5c [0-04] 2e 62 61 74 } //1
		$a_00_4 = {25 37 36 25 32 45 25 37 39 25 36 31 25 36 46 25 33 36 25 33 33 25 32 45 25 36 33 25 36 46 25 36 44 2f 63 6f 6e 66 69 67 2e 61 73 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}