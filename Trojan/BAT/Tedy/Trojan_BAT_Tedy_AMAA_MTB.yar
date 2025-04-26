
rule Trojan_BAT_Tedy_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 26 06 72 ?? 04 00 70 28 ?? 00 00 06 26 06 72 ?? 04 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b 2b 00 07 2a } //4
		$a_80_1 = {67 4d 71 65 57 4f 50 4c 47 56 62 33 37 79 30 30 7a 4d 72 4c 34 2f 56 56 46 48 79 78 42 67 61 6d 2f 55 6b 62 37 62 43 55 33 51 38 3d } //gMqeWOPLGVb37y00zMrL4/VVFHyxBgam/Ukb7bCU3Q8=  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}