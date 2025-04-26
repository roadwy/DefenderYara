
rule Trojan_BAT_NjRat_NECF_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {39 33 64 64 66 37 64 66 2d 37 63 37 66 2d 34 63 64 33 2d 38 61 66 35 2d 64 38 64 32 35 63 32 65 64 64 33 65 } //5 93ddf7df-7c7f-4cd3-8af5-d8d25c2edd3e
		$a_01_1 = {4d 6f 6e 65 6c 61 20 66 61 73 68 69 6f 6e 2e 65 78 65 } //2 Monela fashion.exe
		$a_01_2 = {54 00 72 00 69 00 61 00 6c 00 20 00 45 00 78 00 70 00 69 00 72 00 65 00 64 00 } //2 Trial Expired
		$a_01_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_4 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}