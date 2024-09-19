
rule Adware_MacOS_Adload_J_MTB{
	meta:
		description = "Adware:MacOS/Adload.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f2 0f 59 05 1d 0d 00 00 f2 0f 10 0d 1d 0d 00 00 66 0f 28 d0 f2 0f 5c d1 f2 48 0f 2c c2 48 c7 47 10 00 00 00 00 48 0f ba f8 3f f2 48 0f 2c f0 66 0f 2e c1 48 0f 43 f0 e8 9d fe fe ff 48 8b 4d b8 48 8b 75 c0 48 39 f1 } //1
		$a_03_1 = {4c 89 d0 4d 85 e4 0f ?? ?? ?? ?? ?? 48 29 f2 41 83 f8 02 0f ?? ?? ?? ?? ?? 48 85 d2 0f ?? ?? ?? ?? ?? 48 89 d0 48 d1 f8 31 c9 66 c1 84 4f 00 08 00 00 08 48 ff c1 48 39 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}