
rule Trojan_Win32_Zenpak_RDL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 6a 33 39 4c 36 7a 57 75 34 2e 64 6c 4c } //01 00  0j39L6zWu4.dlL
		$a_01_1 = {34 74 6f 67 65 74 68 65 72 2e 31 39 } //01 00  4together.19
		$a_01_2 = {31 62 65 74 68 69 72 64 33 63 68 65 72 62 73 61 69 64 6e 73 6f 66 69 72 73 74 } //01 00  1bethird3cherbsaidnsofirst
		$a_01_3 = {30 77 68 65 72 65 69 6e 73 68 61 6c 6c 74 6f 67 65 74 68 65 72 77 65 72 65 2e 52 74 66 } //00 00  0whereinshalltogetherwere.Rtf
	condition:
		any of ($a_*)
 
}