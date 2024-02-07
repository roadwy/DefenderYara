
rule Trojan_Win32_Dridex_AR_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 05 fc 55 0e 01 89 02 8b 15 90 01 04 89 44 24 1c a3 90 01 04 8b c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ba 60 01 01 00 ba 9c ad 00 00 a1 90 01 04 a3 90 02 0c 31 0d 90 01 04 c7 05 90 01 08 a1 90 01 04 01 05 90 01 04 8b ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 4d fc 03 0d 90 01 04 8b 55 f4 03 15 90 01 04 8a 02 88 01 33 c9 0f 84 90 01 04 6a 04 6a 04 90 00 } //02 00 
		$a_00_1 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 87 10 00 00 8b 4d 08 89 01 5e 8b e5 5d c3 } //00 00 
		$a_00_2 = {78 60 } //00 00  x`
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AR_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {81 c2 00 73 02 00 89 15 90 01 04 a1 90 01 04 5d 90 0a 32 00 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 89 0d 90 01 04 8b 15 90 00 } //02 00 
		$a_02_1 = {8d 8c 10 9e 9a 56 00 2b 4d b0 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 81 ea 9e 9a 56 00 89 15 90 00 } //00 00 
		$a_00_2 = {78 6b } //00 00  xk
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b ca 88 4d d7 b8 02 00 00 00 6b c8 09 0f b7 91 90 01 04 b8 02 00 00 00 6b c8 06 0f b7 81 90 00 } //03 00 
		$a_80_1 = {53 6f 6c 75 74 69 6f 6e 5f 6f 6e 65 5c 75 73 65 2e 70 64 62 } //Solution_one\use.pdb  03 00 
		$a_80_2 = {43 6f 6d 70 6c 65 74 65 62 65 67 61 6e } //Completebegan  03 00 
		$a_80_3 = {53 65 61 72 63 68 6e 65 69 67 68 62 6f 72 } //Searchneighbor  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AR_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 2c 8b 7c 24 28 81 c7 bb ef 21 47 83 d1 00 89 7c 24 28 89 4c 24 2c 3c 00 89 54 24 0c 88 44 24 0b } //00 00 
	condition:
		any of ($a_*)
 
}