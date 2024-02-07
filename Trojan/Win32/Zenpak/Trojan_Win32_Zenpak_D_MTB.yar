
rule Trojan_Win32_Zenpak_D_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 8b 4d e4 8b 55 e0 01 ca 89 15 90 01 04 8b 4d ec 8a 1c 01 8b 55 e8 88 1c 02 05 01 00 00 00 8b 75 f0 39 f0 89 45 d8 74 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_D_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 51 54 5d 21 48 32 47 } //01 00  hQT]!H2G
		$a_01_1 = {52 6a 50 6b 45 51 4d } //01 00  RjPkEQM
		$a_01_2 = {37 6b 4c 67 72 65 61 74 54 66 72 75 69 74 66 61 63 65 2e 6c 69 66 65 66 72 6f 6d } //01 00  7kLgreatTfruitface.lifefrom
		$a_01_3 = {25 00 4d 00 72 00 52 00 3c 00 4c 00 55 00 57 00 6e 00 32 00 47 00 75 00 66 00 } //01 00  %MrR<LUWn2Guf
		$a_01_4 = {61 46 50 35 24 33 2b 72 23 55 39 52 37 } //01 00  aFP5$3+r#U9R7
		$a_01_5 = {5c 54 4d 54 6e 38 5c 37 6c 72 73 58 53 47 5c 51 64 2e 70 64 62 } //00 00  \TMTn8\7lrsXSG\Qd.pdb
	condition:
		any of ($a_*)
 
}