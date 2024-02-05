
rule Trojan_Win32_IcedID_UR_MTB{
	meta:
		description = "Trojan:Win32/IcedID.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 f9 05 8d 1c 8d 40 03 42 00 8b f0 83 e6 1f 6b f6 38 8b 0b 0f b6 4c 31 04 83 e1 01 74 bf } //01 00 
		$a_01_1 = {41 6f 6b 76 63 4f 69 67 6e 67 69 } //01 00 
		$a_01_2 = {55 71 6d 71 63 57 7a 66 69 6e } //01 00 
		$a_01_3 = {51 66 70 51 6e 75 6d 68 6e 48 63 63 7a 6a 68 65 } //00 00 
	condition:
		any of ($a_*)
 
}