
rule Trojan_Win32_Ertfor_A{
	meta:
		description = "Trojan:Win32/Ertfor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {eb 48 6a 00 68 90 01 02 40 00 6a 01 68 90 01 02 40 00 ff b5 90 01 02 ff ff e8 90 01 02 00 00 a0 90 01 02 40 00 32 85 90 01 02 ff ff a2 90 01 02 40 00 6a 00 90 00 } //03 00 
		$a_01_1 = {0f 84 f2 00 00 00 89 85 fc fd ff ff c7 85 d8 fd ff ff 14 00 00 00 eb 21 6a 00 68 21 28 00 10 6a 08 8d 85 e4 fd ff ff } //01 00 
		$a_01_2 = {33 c5 eb 05 22 25 73 22 00 } //01 00 
		$a_01_3 = {57 49 4e 49 44 00 45 52 52 4f 52 00 } //01 00 
		$a_01_4 = {77 69 6e 6c 6f 67 61 6e 2e 65 78 65 00 } //01 00 
		$a_01_5 = {70 32 68 68 72 2e 62 61 74 00 3a } //01 00 
		$a_01_6 = {3f 69 64 3d 25 73 26 76 65 72 3d } //00 00 
	condition:
		any of ($a_*)
 
}