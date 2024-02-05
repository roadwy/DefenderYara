
rule Trojan_Win32_Alureon_EP{
	meta:
		description = "Trojan:Win32/Alureon.EP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 f8 21 43 65 87 c7 45 e8 2b 02 00 00 } //01 00 
		$a_03_1 = {ff d0 c6 85 90 01 04 e9 c7 85 90 00 } //01 00 
		$a_01_2 = {6d 00 61 00 78 00 73 00 73 00 63 00 6f 00 72 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}