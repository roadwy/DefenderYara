
rule Ransom_Win32_Basta_DP_MTB{
	meta:
		description = "Ransom:Win32/Basta.DP!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 58 52 49 4b 4e 2e 65 78 65 } //05 00  AXRIKN.exe
		$a_01_1 = {b8 08 00 00 00 6b c8 00 8b 55 ec 8b 45 d4 8b 75 e8 8b 14 90 2b 14 0e 03 55 f0 89 55 d0 8b 45 d0 50 8b 4d 08 51 } //01 00 
		$a_01_2 = {4a 41 4f 4a 4e 49 2e 65 78 65 } //05 00  JAOJNI.exe
		$a_01_3 = {8b 4d fc 83 c1 0e 89 4d fc 8b 55 f8 8b 42 08 89 45 f0 8b 4d f8 8b 51 08 8b 45 f0 03 50 3c 89 55 ec 8b 45 fc 99 2b c2 d1 f8 89 45 fc 8b 4d f8 8b 51 08 8b 45 ec 03 50 28 89 55 e8 } //00 00 
	condition:
		any of ($a_*)
 
}