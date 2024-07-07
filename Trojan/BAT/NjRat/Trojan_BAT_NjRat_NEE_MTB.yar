
rule Trojan_BAT_NjRat_NEE_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 46 55 34 6d 62 54 33 47 4d 72 65 74 37 54 48 6f 6e 66 } //3 SFU4mbT3GMret7THonf
		$a_01_1 = {72 45 34 6c 70 6e 54 38 36 33 51 6e 69 6a 4b 51 4b 35 } //3 rE4lpnT863QnijKQK5
		$a_01_2 = {4b 68 32 6f 38 42 53 48 62 64 } //3 Kh2o8BSHbd
		$a_01_3 = {6b 00 72 00 6f 00 77 00 65 00 6d 00 61 00 72 00 46 00 5c 00 54 00 45 00 4e 00 2e 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 3a 00 43 00 } //2 krowemarF\TEN.tfosorciM\swodniW\:C
		$a_01_4 = {39 00 31 00 33 00 30 00 33 00 2e 00 30 00 2e 00 34 00 76 00 } //2 91303.0.4v
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=13
 
}