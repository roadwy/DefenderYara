
rule Trojan_Win64_CobaltStrike_BJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c9 4d 8d 40 01 49 83 f9 64 49 0f 45 c9 0f b6 44 0c 30 41 30 40 ff 33 c0 49 83 f9 64 4c 8d 49 01 0f 45 c2 41 ff c2 8d 50 01 41 81 fa 90 02 04 72 90 00 } //02 00 
		$a_01_1 = {4d 63 56 73 6f 43 66 67 47 65 74 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 2b 3f 02 00 2b 85 90 01 04 8b 95 90 01 04 48 90 01 02 48 90 01 06 48 90 01 02 48 90 01 01 48 90 01 06 0f b6 04 08 88 02 83 85 90 01 05 81 bd 90 00 } //01 00 
		$a_03_1 = {44 0f b6 04 10 8b 85 90 01 04 48 90 01 01 48 90 01 06 0f b6 0c 10 8b 85 90 01 04 48 90 01 02 48 90 01 06 48 90 01 02 44 90 01 02 31 ca 88 10 83 85 90 01 05 83 bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}