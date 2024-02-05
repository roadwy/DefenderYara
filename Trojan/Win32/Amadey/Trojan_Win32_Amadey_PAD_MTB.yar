
rule Trojan_Win32_Amadey_PAD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 00 00 8b 44 24 90 01 01 89 04 24 8b 90 01 01 24 44 31 04 24 8b 04 24 8b 4c 24 90 01 01 89 01 83 c4 3c 90 00 } //01 00 
		$a_03_1 = {01 44 24 18 8b 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 8b c7 c1 e8 05 03 c5 51 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}