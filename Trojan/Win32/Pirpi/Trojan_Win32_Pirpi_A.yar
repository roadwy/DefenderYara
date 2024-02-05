
rule Trojan_Win32_Pirpi_A{
	meta:
		description = "Trojan:Win32/Pirpi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2 } //01 00 
		$a_03_1 = {74 2a 68 01 00 00 7f e8 90 01 04 39 85 90 01 04 74 18 81 bd 90 01 04 bd 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}