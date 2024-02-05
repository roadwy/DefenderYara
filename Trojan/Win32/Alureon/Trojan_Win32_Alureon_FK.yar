
rule Trojan_Win32_Alureon_FK{
	meta:
		description = "Trojan:Win32/Alureon.FK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 e9 ab 56 e8 } //01 00 
		$a_01_1 = {3c 0d 75 04 c6 07 00 47 80 3f 0a } //01 00 
		$a_03_2 = {74 70 80 3f 2f be 90 01 04 6a 01 75 0f 90 00 } //01 00 
		$a_01_3 = {50 75 72 70 6c 65 48 61 7a 65 } //00 00 
	condition:
		any of ($a_*)
 
}