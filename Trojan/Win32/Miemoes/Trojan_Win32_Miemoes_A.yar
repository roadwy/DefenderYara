
rule Trojan_Win32_Miemoes_A{
	meta:
		description = "Trojan:Win32/Miemoes.A,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ff ff 8b f0 bb 84 ff ff ff 81 36 66 d6 ba 13 83 c6 04 43 75 f4 68 ff 00 00 00 8d 84 24 43 05 00 00 50 6a 00 } //01 00 
		$a_01_1 = {6d 69 65 6b 69 65 6d 6f 65 73 } //01 00  miekiemoes
		$a_01_2 = {72 64 73 2e 79 61 68 6f 6f } //01 00  rds.yahoo
		$a_01_3 = {66 6f 72 6d 61 74 3d 72 73 73 } //01 00  format=rss
		$a_01_4 = {69 63 71 00 79 69 6d 67 } //00 00  捩q楹杭
	condition:
		any of ($a_*)
 
}