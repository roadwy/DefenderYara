
rule Trojan_Win32_CobaltStrike_DBC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {81 f1 af 05 00 00 05 12 2d 75 47 01 86 84 00 00 00 8d 87 ba 3d 00 00 56 52 50 8b 44 24 3c 05 79 0a 00 00 51 50 8d 82 85 0b 00 00 35 8b 14 00 00 50 e8 ca a7 ff ff 83 c4 18 81 f5 97 0c 00 00 } //01 00 
		$a_01_1 = {57 68 74 77 6f 74 30 32 38 6d 37 32 } //01 00 
		$a_01_2 = {53 6e 73 42 33 30 37 68 } //00 00 
	condition:
		any of ($a_*)
 
}