
rule Trojan_Win64_CobaltStrike_AL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 29 c0 8b 05 90 01 04 41 29 c0 44 89 c0 4c 63 c0 48 8b 45 90 01 01 4c 01 c0 0f b6 00 31 c8 88 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 10 48 89 74 24 18 57 48 83 ec 10 33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b 90 01 01 41 81 f0 6e 74 65 6c 41 81 90 01 05 44 8b 90 01 01 8b f0 33 c9 41 8d 43 01 45 0b 90 00 } //01 00 
		$a_03_1 = {0f a2 41 81 90 01 05 89 04 24 45 0b 90 01 01 89 5c 24 04 8b f9 89 4c 24 08 89 54 24 0c 75 90 01 01 48 83 0d 90 01 05 25 f0 3f ff 0f 90 00 } //01 00 
		$a_03_2 = {ff ff ff ff 72 62 00 00 00 00 00 00 90 02 30 2e 62 69 6e 90 00 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_5 = {66 6f 70 65 6e } //01 00  fopen
		$a_01_6 = {66 73 65 65 6b } //01 00  fseek
		$a_01_7 = {66 74 65 6c 6c } //01 00  ftell
		$a_01_8 = {6d 61 6c 6c 6f 63 } //01 00  malloc
		$a_01_9 = {66 72 65 61 64 } //00 00  fread
	condition:
		any of ($a_*)
 
}