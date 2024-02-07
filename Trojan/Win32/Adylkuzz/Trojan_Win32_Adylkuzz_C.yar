
rule Trojan_Win32_Adylkuzz_C{
	meta:
		description = "Trojan:Win32/Adylkuzz.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 69 73 67 6f 67 6f 77 65 62 2e 63 6f 6d 2f 38 36 2e 65 78 65 } //01 00  .disgogoweb.com/86.exe
		$a_03_1 = {4d 69 6e 65 72 90 01 01 65 78 65 6e 61 6d 65 90 02 08 4c 4d 53 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {5c 46 6f 6e 74 73 5c 4c 4d 53 2e 65 78 65 } //01 00  \Fonts\LMS.exe
		$a_03_3 = {73 70 70 73 72 76 2e 65 78 65 90 02 04 53 65 72 76 65 72 90 00 } //01 00 
		$a_03_4 = {64 69 73 70 6c 61 79 90 02 04 4d 69 63 72 6f 73 6f 66 74 20 2e 4e 45 54 20 46 72 61 6d 65 77 6f 72 6b 20 4e 47 45 4e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}