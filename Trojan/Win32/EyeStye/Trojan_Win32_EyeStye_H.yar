
rule Trojan_Win32_EyeStye_H{
	meta:
		description = "Trojan:Win32/EyeStye.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 54 45 4e 59 50 53 5f 5f } //01 00  _TENYPS__
		$a_02_1 = {6c 6d 78 2e 90 02 08 2d 73 65 69 6b 6f 6f 63 90 00 } //01 00 
		$a_00_2 = {45 4d 41 4e 54 4f 42 25 } //01 00  EMANTOB%
		$a_02_3 = {1b 6a 00 43 dc fe 04 dc fe 04 0c ff 0a 08 00 08 00 04 b0 fe 04 0c ff fd fe 90 01 01 fe 04 3c ff fd fe 90 01 01 fe 07 08 00 80 00 24 0a 00 0d 20 00 0b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EyeStye_H_2{
	meta:
		description = "Trojan:Win32/EyeStye.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 03 00 "
		
	strings :
		$a_03_0 = {ff 6e c6 85 90 01 02 ff ff 44 c6 85 90 01 02 ff ff 72 c6 85 90 01 02 ff ff 69 c6 85 90 01 02 ff ff 76 c6 85 90 01 02 ff ff 78 c6 85 90 01 02 ff ff 78 90 00 } //03 00 
		$a_03_1 = {ff 6e c6 85 9f fb 90 01 02 66 c6 85 a0 fb 90 01 02 69 c6 85 a1 fb 90 01 02 67 c6 85 a2 fb 90 01 02 2e c6 85 a3 fb 90 01 02 62 c6 85 a4 fb 90 01 02 69 90 00 } //02 00 
		$a_01_2 = {5f 5f 53 50 59 4e 45 54 5f 5f } //01 00  __SPYNET__
		$a_01_3 = {53 70 79 45 79 65 5f 53 74 6f 70 00 } //01 00  灓䕹敹卟潴p
		$a_01_4 = {53 70 79 45 79 65 5f 49 6e 69 74 00 } //01 00  灓䕹敹䥟楮t
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 67 6c 6f 62 70 6c 75 67 69 6e 73 70 69 70 65 00 } //01 00 
		$a_01_6 = {45 72 72 6f 72 3a 20 54 68 72 65 61 64 20 69 73 20 72 65 61 6c 6c 79 20 73 6c 6f 70 70 79 00 } //01 00 
		$a_01_7 = {62 6f 74 5f 67 75 69 64 00 } //01 00 
		$a_01_8 = {25 42 4f 54 4e 41 4d 45 25 00 } //00 00  䈥呏䅎䕍%
	condition:
		any of ($a_*)
 
}