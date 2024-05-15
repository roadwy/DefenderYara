
rule Trojan_Win32_DarkGate_EM_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 6d 70 70 5c 41 75 74 6f 69 74 33 2e 65 78 65 20 63 3a 5c 74 6d 70 70 5c 74 65 73 74 2e 61 75 33 } //01 00  c:\tmpp\Autoit3.exe c:\tmpp\test.au3
		$a_81_1 = {63 3a 5c 64 65 62 75 67 67 } //01 00  c:\debugg
		$a_81_2 = {6e 6f 72 65 73 64 61 74 61 } //01 00  noresdata
		$a_81_3 = {64 65 62 75 67 78 32 } //00 00  debugx2
	condition:
		any of ($a_*)
 
}