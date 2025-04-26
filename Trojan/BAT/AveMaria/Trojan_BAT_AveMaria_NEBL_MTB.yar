
rule Trojan_BAT_AveMaria_NEBL_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 30 66 61 36 62 38 63 66 2d 32 31 65 62 2d 34 36 65 37 2d 62 32 61 34 2d 37 65 63 35 65 35 64 62 63 37 33 34 } //5 $0fa6b8cf-21eb-46e7-b2a4-7ec5e5dbc734
		$a_01_1 = {4e 56 43 56 58 4e 4a 44 46 47 4a 4b 44 46 2e 70 64 62 } //3 NVCVXNJDFGJKDF.pdb
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //3 Confuser.Core 1.6.0+447341964f
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=11
 
}