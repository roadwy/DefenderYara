
rule Trojan_Win32_Amadey_AM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 85 c8 81 43 00 32 04 19 8b 4d f8 88 83 10 61 43 00 43 3b 5d fc } //00 00 
	condition:
		any of ($a_*)
 
}