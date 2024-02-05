
rule Trojan_Win32_Typhon_MBHI_MTB{
	meta:
		description = "Trojan:Win32/Typhon.MBHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 84 24 a0 02 00 00 03 c1 66 90 01 03 a2 02 00 00 41 83 f9 33 72 90 00 } //01 00 
		$a_01_1 = {6c 74 78 71 6b 63 62 77 77 73 6a 62 6f 6e 70 00 72 76 78 67 64 79 72 } //00 00 
	condition:
		any of ($a_*)
 
}