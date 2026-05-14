
rule Trojan_BAT_DarkCloud_RVB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.RVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 9d a2 29 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 ?? 00 00 00 22 00 00 00 ?? 01 00 00 bf 00 00 00 73 00 00 00 e9 00 00 00 03 00 00 00 29 00 00 00 0b 00 00 00 28 00 00 00 04 00 00 00 0a 00 00 00 0b 00 00 00 11 00 00 00 0e 00 00 00 02 00 00 00 08 00 00 00 04 00 00 00 13 00 00 00 02 00 00 00 08 } //1
		$a_81_1 = {4c 61 73 65 72 43 61 6c 63 75 6c 61 74 6f 72 } //1 LaserCalculator
		$a_81_2 = {67 65 74 5f 66 69 6e 6e } //1 get_finn
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}