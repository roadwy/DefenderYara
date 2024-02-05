
rule Trojan_Win32_Amadey_CAJ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 04 85 e8 a2 43 00 32 04 31 8b 4d ec 88 86 90 01 04 46 3b 75 e4 7c 90 01 01 81 fe 90 01 04 0f 90 00 } //01 00 
		$a_01_1 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}