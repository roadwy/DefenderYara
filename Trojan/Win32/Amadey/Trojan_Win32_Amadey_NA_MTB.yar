
rule Trojan_Win32_Amadey_NA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 f8 10 88 04 3a 8b c1 c1 f8 08 88 44 3a 01 8b c2 88 4c 38 02 83 c7 03 83 6c 24 28 01 75 a3 } //05 00 
		$a_01_1 = {8d 42 ff c1 e8 02 83 c6 02 40 } //00 00 
	condition:
		any of ($a_*)
 
}