
rule Trojan_Win32_Kuta_A{
	meta:
		description = "Trojan:Win32/Kuta.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 c7 45 97 01 31 33 c0 5a 59 59 } //01 00 
		$a_01_1 = {6e 6f 67 61 2d 72 75 6b 61 } //01 00 
		$a_01_2 = {73 74 61 74 2f 74 75 6b 2f } //00 00 
	condition:
		any of ($a_*)
 
}