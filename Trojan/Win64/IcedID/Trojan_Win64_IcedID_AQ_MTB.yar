
rule Trojan_Win64_IcedID_AQ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 36 35 56 37 67 6c 71 45 71 69 39 6a 6a 75 79 4d 4c 49 } //01 00  B65V7glqEqi9jjuyMLI
		$a_01_1 = {45 43 73 55 71 78 75 48 33 57 6b 31 55 6b 4e 50 52 4f 4a 49 5a 6a } //01 00  ECsUqxuH3Wk1UkNPROJIZj
		$a_01_2 = {4e 62 4f 41 43 38 30 63 68 70 74 61 6e 75 65 31 58 59 4c } //01 00  NbOAC80chptanue1XYL
		$a_01_3 = {4f 72 6d 31 35 58 64 72 78 4e 38 65 64 71 4e 54 76 71 43 4f 63 61 74 30 72 } //01 00  Orm15XdrxN8edqNTvqCOcat0r
		$a_01_4 = {52 32 44 37 77 36 74 50 34 38 6d 44 79 61 74 34 41 76 4d 50 72 65 34 66 39 72 38 5a 58 } //01 00  R2D7w6tP48mDyat4AvMPre4f9r8ZX
		$a_01_5 = {54 70 79 53 72 6b 56 64 69 76 44 7a 49 58 78 35 31 39 4d 6f } //01 00  TpySrkVdivDzIXx519Mo
		$a_01_6 = {55 46 43 58 37 37 32 34 35 69 62 36 6a 7a 6e 39 31 4f 76 } //01 00  UFCX77245ib6jzn91Ov
		$a_01_7 = {56 6a 65 6d 30 6b 6e 48 57 75 47 59 71 59 42 57 49 72 57 46 61 37 56 72 46 } //00 00  Vjem0knHWuGYqYBWIrWFa7VrF
	condition:
		any of ($a_*)
 
}