
rule Trojan_BAT_njRat_MBXH_MTB{
	meta:
		description = "Trojan:BAT/njRat.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 08 6f 94 00 00 0a 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 } //5
		$a_01_1 = {33 61 39 62 66 64 66 38 65 62 61 34 34 35 35 61 34 2e 72 65 73 6f 75 72 } //3 3a9bfdf8eba4455a4.resour
		$a_01_2 = {6c 76 65 00 53 65 72 76 65 72 20 6e 65 77 } //2 癬e敓癲牥渠睥
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}