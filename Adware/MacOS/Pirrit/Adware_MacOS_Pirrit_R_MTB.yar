
rule Adware_MacOS_Pirrit_R_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.R!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 05 54 8d 11 00 34 c9 88 05 4f 8d 11 00 8a 05 47 8d 11 00 34 bf 88 05 42 8d 11 00 8a 05 3a 8d 11 00 34 fc 88 05 35 8d 11 00 66 0f 6e 05 30 8d 11 00 8a 05 2e 8d 11 00 8d ?? ?? 04 4c } //1
		$a_03_1 = {48 8b 43 38 49 89 46 28 48 8b 43 20 49 89 46 20 4c 89 ef 48 8b 75 d0 4c 89 e2 4c 89 f9 4d 89 f0 e8 ?? ?? ?? ?? 4c 89 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}