
rule Adware_MacOS_Pirrit_V_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.V!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 3a 0e c3 fe 40 0f b6 d6 66 0f 3a 20 c2 08 66 0f f8 d0 66 0f ef e3 0f 28 05 e3 22 1f 00 66 0f 38 10 d4 88 0d bc 50 22 00 } //1
		$a_01_1 = {49 89 f2 49 89 d1 49 89 c8 31 c9 85 c0 0f 94 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}