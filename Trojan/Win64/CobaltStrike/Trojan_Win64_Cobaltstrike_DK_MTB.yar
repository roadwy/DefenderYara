
rule Trojan_Win64_Cobaltstrike_DK_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 28 4c 08 d0 0f 57 c8 0f 28 54 08 e0 0f 57 d0 0f 29 4c 08 d0 0f 29 54 08 e0 0f 28 4c 08 f0 0f 57 c8 0f 28 14 08 0f 57 d0 0f 29 4c 08 f0 0f 29 14 08 48 83 c0 90 01 01 48 3d 90 02 05 75 90 00 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 43 6f 64 65 4c 6f 61 64 65 72 5c 62 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}