
rule Trojan_Win32_Fauppod_SPD_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 75 62 64 75 65 70 52 64 65 65 70 74 68 65 72 65 61 6c 6c 2e 6b 57 66 72 75 69 74 66 75 6c 35 } //01 00  subduepRdeepthereall.kWfruitful5
		$a_01_1 = {73 6b 34 49 74 45 73 74 61 72 73 64 6f 6d 69 6e 69 6f 6e 61 73 65 61 73 6d 69 64 73 74 } //01 00  sk4ItEstarsdominionaseasmidst
		$a_01_2 = {64 6f 6e 2e 74 43 76 67 72 65 61 74 65 72 41 6c 6c } //01 00  don.tCvgreaterAll
		$a_01_3 = {37 6c 65 74 4f 6e 69 74 6f } //01 00  7letOnito
		$a_01_4 = {4a 49 71 57 68 65 72 65 69 6e 6d 6f 76 65 74 68 44 61 79 70 76 66 6f 72 6d } //01 00  JIqWhereinmovethDaypvform
		$a_01_5 = {44 43 72 65 65 70 65 74 68 63 72 65 65 70 65 74 68 58 } //01 00  DCreepethcreepethX
		$a_01_6 = {63 72 65 65 70 65 74 68 6c 69 76 69 6e 67 39 61 69 72 2e 35 65 71 } //01 00  creepethliving9air.5eq
		$a_01_7 = {42 4e 77 68 61 6c 65 73 68 69 6d 68 69 73 77 6d 61 6c 65 43 67 72 65 61 74 53 } //01 00  BNwhaleshimhiswmaleCgreatS
		$a_01_8 = {62 33 47 72 65 61 74 65 72 6b 77 4f 73 65 61 44 68 61 64 } //00 00  b3GreaterkwOseaDhad
	condition:
		any of ($a_*)
 
}