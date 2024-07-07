
rule Trojan_Win32_DarkGate_EM_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 6d 70 70 5c 41 75 74 6f 69 74 33 2e 65 78 65 20 63 3a 5c 74 6d 70 70 5c 74 65 73 74 2e 61 75 33 } //1 c:\tmpp\Autoit3.exe c:\tmpp\test.au3
		$a_81_1 = {63 3a 5c 64 65 62 75 67 67 } //1 c:\debugg
		$a_81_2 = {6e 6f 72 65 73 64 61 74 61 } //1 noresdata
		$a_81_3 = {64 65 62 75 67 78 32 } //1 debugx2
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}