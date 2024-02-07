
rule Trojan_BAT_Razy_DHA_MTB{
	meta:
		description = "Trojan:BAT/Razy.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {75 69 79 61 65 68 66 69 75 77 61 6e 66 } //01 00  uiyaehfiuwanf
		$a_81_1 = {73 64 66 6a 68 61 69 68 77 75 34 68 39 } //01 00  sdfjhaihwu4h9
		$a_81_2 = {39 30 73 6a 66 69 6f 61 6a 77 34 77 39 6f } //01 00  90sjfioajw4w9o
		$a_81_3 = {75 73 68 66 67 61 38 39 68 66 38 77 39 65 } //01 00  ushfga89hf8w9e
		$a_81_4 = {73 75 79 68 33 38 37 72 71 68 39 49 41 53 48 4a } //00 00  suyh387rqh9IASHJ
	condition:
		any of ($a_*)
 
}