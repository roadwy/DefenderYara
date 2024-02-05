
rule Trojan_Win32_CobaltStrike_SK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 31 46 48 8b 46 90 01 01 83 f0 90 01 01 01 46 90 01 01 8b 46 90 01 01 2d 90 01 04 31 86 90 01 04 b8 90 01 04 2b 46 90 01 01 01 86 90 01 04 8b 8e 90 01 04 8b 46 90 00 } //01 00 
		$a_00_1 = {52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_SK_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.SK!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 46 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 54 65 6e 63 65 6e 74 69 64 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 4d 4f 20 31 20 2f 54 52 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 74 65 6e 63 65 6e 74 73 6f 73 6f 2e 65 78 65 } //05 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 63 69 61 2e 70 6c 61 6e } //01 00 
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 53 69 64 65 42 61 72 2e 64 6c 6c } //00 00 
		$a_01_3 = {00 78 } //57 00 
	condition:
		any of ($a_*)
 
}