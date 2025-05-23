
rule Trojan_BAT_AgentTesla_NGC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {30 45 31 46 42 41 30 45 30 30 42 34 30 39 43 44 32 31 42 38 30 31 34 43 43 44 32 31 35 34 36 38 36 39 37 33 32 30 37 30 37 32 36 46 36 37 37 32 36 31 } //1 0E1FBA0E00B409CD21B8014CCD21546869732070726F677261
		$a_01_1 = {32 30 37 32 37 35 36 45 32 30 36 39 36 45 32 30 34 34 34 46 35 33 32 30 36 44 36 46 36 34 36 35 32 45 30 44 30 } //1 2072756E20696E20444F53206D6F64652E0D0
		$a_01_2 = {32 45 37 34 36 35 37 38 37 34 30 30 30 30 30 30 31 34 34 31 30 } //1 2E7465787400000014410
		$a_01_3 = {34 44 35 41 39 30 30 30 30 33 30 30 30 30 30 30 30 34 30 30 30 30 30 30 46 46 46 46 30 30 30 30 42 38 } //1 4D5A90000300000004000000FFFF0000B8
		$a_01_4 = {34 43 30 31 35 31 30 30 45 30 33 45 30 30 30 30 30 38 30 30 39 33 30 30 37 34 30 39 35 36 30 31 35 31 30 } //1 4C015100E03E00000800930074095601510
		$a_01_5 = {30 30 36 31 30 30 36 44 30 30 36 35 30 30 30 30 30 30 35 33 30 30 36 31 30 30 36 36 30 30 36 35 30 30 35 33 } //1 0061006D0065000000530061006600650053
		$a_01_6 = {36 46 30 30 36 45 30 30 30 30 30 30 33 34 30 30 32 45 30 30 33 30 30 30 32 45 30 30 33 35 30 30 32 45 30 30 33 } //1 6F006E00000034002E0030002E0035002E003
		$a_01_7 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_NGC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {f2 02 f4 02 0f 03 ef 02 df 02 df 02 eb 02 df 02 df 02 df 02 df 02 e3 02 df 02 df 02 df 02 df 02 cd 02 cd 02 d6 02 df 02 df 02 ea 02 05 03 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 ef } //1
		$a_01_1 = {03 05 03 d2 02 df 02 12 03 df 02 0c 03 ec 02 e7 02 00 03 05 03 e0 02 f2 02 eb 02 ce 02 06 03 f4 02 e5 02 06 03 0e 03 01 03 17 03 e0 02 15 03 01 } //1
		$a_01_2 = {02 07 03 e3 02 ea 02 df 02 ef 02 05 03 df 02 df 02 e2 02 0d 03 df 02 df 02 df 02 df 02 e5 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 e2 } //1
		$a_01_3 = {02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 e0 02 ef 02 df 02 df 02 df 02 eb 02 df 02 df 02 df 02 df 02 e3 02 e2 02 05 03 df 02 df 02 df 02 df 02 df 02 } //1
		$a_01_4 = {12 03 df 02 e5 02 e7 02 df 02 00 03 df 02 e0 02 d3 02 df 02 e1 02 df 02 df 02 f4 02 05 03 e0 02 0a 03 df 02 e6 02 e7 02 df 02 01 03 15 03 e0 02 0e 03 df 02 e5 } //1
		$a_01_5 = {5f 41 00 5f 42 00 5f 43 00 5f 44 00 5f 45 00 5f 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}