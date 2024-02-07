
rule Trojan_Win32_Emotet_CX{
	meta:
		description = "Trojan:Win32/Emotet.CX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d c2 0c 00 89 35 90 01 02 51 00 e8 90 01 02 ff ff 89 45 fc c3 5a 01 ca 89 15 90 00 } //01 00 
		$a_00_1 = {23 23 47 57 45 48 4a 45 54 4b 45 54 52 52 45 4a 52 45 55 45 52 2a 2a 2a } //01 00  ##GWEHJETKETRREJREUER***
		$a_00_2 = {44 00 65 00 6d 00 6f 00 53 00 68 00 69 00 65 00 6c 00 64 00 20 00 44 00 65 00 73 00 69 00 67 00 6e 00 65 00 72 00 } //03 00  DemoShield Designer
		$a_00_3 = {72 34 62 35 6c 65 64 3d 22 54 72 75 6e 75 72 74 79 2e 70 64 62 } //00 00  r4b5led="Trunurty.pdb
	condition:
		any of ($a_*)
 
}