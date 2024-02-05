
rule Trojan_Win32_Amadey_ITI_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ITI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 8d 3c 33 c7 05 90 01 08 c7 05 90 01 08 89 4c 24 10 8b 44 24 20 01 44 24 10 81 3d 90 01 08 75 0d 8d 54 24 90 01 01 52 6a 00 ff 15 90 01 04 8b 44 24 10 33 c7 31 44 24 0c 8b 44 24 0c 29 44 24 14 8b 15 90 01 04 81 fa 90 01 04 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}