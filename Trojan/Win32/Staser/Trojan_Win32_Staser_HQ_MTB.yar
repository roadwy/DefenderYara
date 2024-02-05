
rule Trojan_Win32_Staser_HQ_MTB{
	meta:
		description = "Trojan:Win32/Staser.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 0f a2 89 45 fc 89 5d f8 89 4d ec 89 55 f0 b8 01 00 00 00 0f a2 } //01 00 
		$a_01_1 = {8b 45 f8 3d 47 65 6e 75 75 1b 8b 45 f0 3d 69 6e 65 49 75 11 8b 45 ec 3d 6e 74 65 6c } //01 00 
		$a_01_2 = {40 2e 76 69 72 74 } //01 00 
		$a_01_3 = {41 6c 70 68 61 42 6c 65 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}