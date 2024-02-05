
rule Trojan_Win32_FlyStudio_CC_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 48 ff 8a 58 fe 02 d9 88 58 fe 8a 18 02 d9 88 18 03 c6 4a 75 ea } //01 00 
		$a_00_1 = {8b d0 33 db 8a 19 81 e2 ff 00 00 00 33 d3 c1 e8 08 8b 14 95 60 8b 60 00 33 c2 41 4e 75 e2 } //01 00 
		$a_00_2 = {8a 1e 8a c8 d2 eb 80 e3 0f 83 f8 04 88 5d 00 75 05 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}