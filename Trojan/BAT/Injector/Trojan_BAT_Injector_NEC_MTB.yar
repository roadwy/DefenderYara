
rule Trojan_BAT_Injector_NEC_MTB{
	meta:
		description = "Trojan:BAT/Injector.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 34 35 31 36 45 30 45 31 2d 35 43 30 45 2d 34 42 34 45 2d 39 41 33 32 2d 39 45 33 37 45 32 33 45 37 34 32 36 } //5 $4516E0E1-5C0E-4B4E-9A32-9E37E23E7426
		$a_01_1 = {59 69 70 70 48 42 2e 64 6c 6c } //5 YippHB.dll
		$a_01_2 = {38 00 2e 00 38 00 37 00 2e 00 30 00 2e 00 34 00 30 00 36 00 } //4 8.87.0.406
		$a_01_3 = {50 50 73 78 74 71 69 55 } //3 PPsxtqiU
		$a_01_4 = {50 6f 6c 77 4b 62 } //3 PolwKb
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=21
 
}