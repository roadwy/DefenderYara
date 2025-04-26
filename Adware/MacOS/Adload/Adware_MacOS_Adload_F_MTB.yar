
rule Adware_MacOS_Adload_F_MTB{
	meta:
		description = "Adware:MacOS/Adload.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 48 c1 e1 08 8b 85 58 fc ff ff 48 09 c8 49 c1 e7 10 49 09 c7 89 d8 48 c1 e0 18 4c 09 f8 48 3d 50 4b 03 04 41 bc 99 ff ff ff b8 00 00 00 00 44 0f 44 e0 } //1
		$a_03_1 = {4c 8b b5 c0 fc ff ff 4c 29 f3 48 89 d8 48 ff c0 0f 88 ?? ?? ?? ?? 49 bd ff ff ff ff ff ff ff 7f 48 b9 ff ff ff ff ff ff ff 3f 48 39 cb 73 ?? 4c 8d 2c 1b 49 39 c5 4c 0f 42 e8 4d 85 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}