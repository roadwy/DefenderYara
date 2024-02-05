
rule Virus_Win32_Virut_AT{
	meta:
		description = "Virus:Win32/Virut.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {cd 2e c1 e0 1f 79 18 } //01 00 
		$a_03_1 = {55 b8 00 40 00 00 2b c9 87 6c 24 04 f7 d1 89 6c 24 04 81 6c 24 04 90 01 04 8d 84 01 b3 fe ff ff 90 90 85 c0 79 9f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}