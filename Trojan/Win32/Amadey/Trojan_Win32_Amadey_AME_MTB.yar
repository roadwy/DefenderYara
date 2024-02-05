
rule Trojan_Win32_Amadey_AME_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c3 23 c3 68 90 01 04 8d 8d 90 01 04 e8 90 01 04 c6 85 90 01 04 47 c6 85 90 01 04 03 c6 85 90 01 04 96 c6 85 90 01 04 0e c6 85 90 01 04 81 c6 85 90 01 04 a0 c6 85 90 01 04 3c c6 85 90 01 04 3b c6 85 90 01 04 33 c6 85 90 01 04 96 c6 85 90 01 04 1a c6 85 90 01 04 4d c6 85 90 01 04 b4 c6 85 90 01 04 e8 c6 85 90 01 04 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}