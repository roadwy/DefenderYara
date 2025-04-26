
rule Trojan_MacOS_Nukesped_L_MTB{
	meta:
		description = "Trojan:MacOS/Nukesped.L!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 f6 4c 89 f2 48 89 c1 e8 46 08 00 00 49 89 c7 49 89 d4 48 89 df 48 8b 75 b0 48 8b 45 b8 ff 50 08 4c 89 e0 48 c1 e8 38 3d fe 00 00 00 } //1
		$a_01_1 = {48 89 df 31 f6 4c 89 f2 48 89 c1 e8 46 08 00 00 49 89 c7 49 89 d4 48 89 df 48 8b 75 b0 48 8b 45 b8 ff 50 08 4c 89 e0 48 c1 e8 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}