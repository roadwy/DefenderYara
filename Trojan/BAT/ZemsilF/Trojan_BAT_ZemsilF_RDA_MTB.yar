
rule Trojan_BAT_ZemsilF_RDA_MTB{
	meta:
		description = "Trojan:BAT/ZemsilF.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 38 64 37 61 36 32 33 2d 38 33 65 35 2d 34 39 61 33 2d 38 37 36 38 2d 37 65 62 36 31 38 63 62 66 32 62 38 } //1 f8d7a623-83e5-49a3-8768-7eb618cbf2b8
		$a_01_1 = {71 00 6c 00 74 00 6b 00 54 00 6f 00 6f 00 6c 00 42 00 69 00 6e 00 67 00 6f 00 } //1 qltkToolBingo
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //1 ConfuserEx v1.0.0
		$a_01_3 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}