
rule Trojan_Win32_Remcos_HL_MTB{
	meta:
		description = "Trojan:Win32/Remcos.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f7 8b c7 c1 e8 02 83 e6 03 8b ce c1 e1 03 8d 34 b0 8d 04 90 ba ff 00 00 00 8b 44 83 18 d3 e2 23 c2 8b 55 fc d3 e8 30 04 1e 47 83 ff 10 7c d0 } //01 00 
		$a_81_1 = {53 23 71 2d 7d 3d 36 7b 29 42 75 45 56 5b 47 44 65 5a 79 3e 7e 4d 35 44 2f 50 26 51 7d 37 3c } //00 00 
	condition:
		any of ($a_*)
 
}