
rule Trojan_BAT_AgentTesla_ASCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 8e 2d 06 16 28 90 01 01 00 00 0a 20 88 13 00 00 28 90 01 01 00 00 0a 2b e1 90 00 } //01 00 
		$a_01_1 = {4d 51 5c 7e 5a 46 43 59 75 5b 59 79 6a 49 65 7a 44 69 74 32 4e 61 68 68 4c 61 7c 5f 68 7b 76 72 77 7d 3d 73 7c 30 7c 73 79 7b 66 4a 5a 48 } //01 00  MQ\~ZFCYu[YyjIezDit2NahhLa|_h{vrw}=s|0|sy{fJZH
		$a_01_2 = {24 65 39 35 61 39 39 31 33 2d 30 33 34 63 2d 34 30 64 35 2d 39 38 63 30 2d 36 35 33 62 33 34 32 65 62 30 30 65 } //00 00  $e95a9913-034c-40d5-98c0-653b342eb00e
	condition:
		any of ($a_*)
 
}