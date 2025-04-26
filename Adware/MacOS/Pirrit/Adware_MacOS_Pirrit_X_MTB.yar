
rule Adware_MacOS_Pirrit_X_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.X!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 05 d1 b9 0a 00 8d 0c 00 80 e1 10 28 c8 04 88 88 05 ce b9 0a 00 8a 05 bc b9 0a 00 34 7e 88 05 c1 b9 0a 00 8a 05 af b9 0a 00 34 7d 88 05 b4 b9 0a 00 8a 05 a2 b9 0a 00 34 e0 } //1
		$a_03_1 = {c7 05 ce 2b 0c 00 01 00 00 00 31 ff be 0a 00 00 00 e8 ?? ?? ?? ?? 48 8d 35 3f 36 0a 00 48 89 c7 e8 ?? ?? ?? ?? 48 89 c3 49 89 e4 49 83 c4 f0 4c 89 e4 48 89 e0 48 83 c0 b0 48 89 c4 48 89 e1 48 83 c1 b0 48 89 cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}