
rule Worm_Win32_Eggnog_E_MTB{
	meta:
		description = "Worm:Win32/Eggnog.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 00 c4 3d 40 00 88 3d 40 00 a0 54 40 00 1c 54 40 } //01 00 
		$a_01_1 = {57 6f 72 6d 2e 50 32 50 2e 47 6f 6f 67 6c 65 } //01 00  Worm.P2P.Google
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4c 69 6d 65 57 69 72 65 } //01 00  SOFTWARE\LimeWire
		$a_01_3 = {55 6e 69 6e 73 74 61 6c 6c 5c 65 44 6f 6e 6b 65 79 32 30 30 30 } //01 00  Uninstall\eDonkey2000
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 58 6f 6c 6f 78 } //00 00  Software\Xolox
	condition:
		any of ($a_*)
 
}