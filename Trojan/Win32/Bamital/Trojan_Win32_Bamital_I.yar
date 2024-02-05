
rule Trojan_Win32_Bamital_I{
	meta:
		description = "Trojan:Win32/Bamital.I,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 62 5f 74 6c 73 74 22 3e 3c } //01 00 
		$a_01_1 = {00 67 7a 69 70 00 73 64 63 68 00 } //01 00 
		$a_01_2 = {00 5b 25 6b 65 79 5d 00 5b 25 73 75 62 69 64 5d 00 } //00 00 
	condition:
		any of ($a_*)
 
}