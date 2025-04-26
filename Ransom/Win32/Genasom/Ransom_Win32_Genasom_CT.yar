
rule Ransom_Win32_Genasom_CT{
	meta:
		description = "Ransom:Win32/Genasom.CT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4f 45 52 55 45 35 54 38 52 37 46 52 47 42 57 33 34 59 4a 54 52 54 44 46 4e 51 32 00 } //1 䕏啒㕅㡔㝒剆䉇㍗头告呒䙄兎2
		$a_01_1 = {25 75 73 65 72 70 72 6f 66 69 6c 45 25 5c } //1 %userprofilE%\
		$a_00_2 = {c7 85 d8 f2 ff ff 4b 00 65 00 c7 85 dc f2 ff ff 72 00 6e 00 c7 85 e0 f2 ff ff 65 00 6c 00 c7 85 e4 f2 ff ff 33 00 32 00 c7 85 e8 f2 ff ff 2e 00 64 00 c7 85 ec f2 ff ff 6c 00 6c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}