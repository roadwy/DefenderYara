
rule Trojan_BAT_NjRat_NEDC_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 64 34 64 37 39 31 66 31 2d 37 31 65 35 2d 34 35 38 64 2d 39 31 38 61 2d 39 38 65 61 63 39 34 36 38 36 34 31 } //5 $d4d791f1-71e5-458d-918a-98eac9468641
		$a_01_1 = {65 00 2d 00 74 00 69 00 63 00 6b 00 65 00 74 00 20 00 66 00 6f 00 72 00 20 00 68 00 6d 00 } //4 e-ticket for hm
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1) >=10
 
}