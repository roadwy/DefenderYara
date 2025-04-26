
rule Trojan_BAT_DarkTortilla_RDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 66 36 61 61 34 64 30 2d 33 34 65 64 2d 34 37 66 30 2d 38 66 64 61 2d 39 66 38 36 36 63 63 35 31 35 33 61 } //1 1f6aa4d0-34ed-47f0-8fda-9f866cc5153a
		$a_01_1 = {4c 66 32 34 } //1 Lf24
		$a_01_2 = {79 37 5a 32 4e } //1 y7Z2N
		$a_01_3 = {43 6a 37 35 57 } //1 Cj75W
		$a_01_4 = {73 32 51 30 48 } //1 s2Q0H
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}