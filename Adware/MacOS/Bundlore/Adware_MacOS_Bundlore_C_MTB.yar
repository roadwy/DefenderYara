
rule Adware_MacOS_Bundlore_C_MTB{
	meta:
		description = "Adware:MacOS/Bundlore.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 49 89 f6 48 8b 05 ef 2d 00 00 ff e0 } //1
		$a_03_1 = {31 c9 85 c0 0f 94 c1 48 8d 05 ?? 2d 00 00 ff 24 c8 ff 25 ?? 2d 00 00 } //1
		$a_03_2 = {48 89 df e8 ?? ?? 00 00 ff 25 ?? ?? 00 00 31 c0 5b 41 5e 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}