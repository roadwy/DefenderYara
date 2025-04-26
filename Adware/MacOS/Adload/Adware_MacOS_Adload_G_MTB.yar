
rule Adware_MacOS_Adload_G_MTB{
	meta:
		description = "Adware:MacOS/Adload.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 63 c7 42 8a 04 28 42 32 44 35 c0 8b 4d a8 88 45 a8 4c 89 e7 48 8d 75 a8 e8 6e be ff ff 8b 45 a8 45 85 ff } //1
		$a_01_1 = {8a 4b 10 88 08 48 83 c3 08 48 ff c0 48 8b 1b 49 39 df } //1
		$a_03_2 = {b8 ff ff ff ff 83 fe 10 75 ?? 40 80 cf 20 89 f9 80 c1 9f 80 f9 05 77 ?? 40 0f b6 c7 83 c0 a9 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}