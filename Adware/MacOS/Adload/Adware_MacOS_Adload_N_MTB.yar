
rule Adware_MacOS_Adload_N_MTB{
	meta:
		description = "Adware:MacOS/Adload.N!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 39 de 0f 86 b0 03 00 00 8a 44 19 ff 8b 0c 19 44 01 e1 28 c8 88 85 0f ff ff ff 48 8b 8d f8 fe ff ff 48 3b 8d 00 ff ff ff 73 0b 88 01 48 ff 85 f8 fe ff ff } //1
		$a_03_1 = {44 8b 68 04 48 89 df e8 ?? ?? ?? 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2 } //1
		$a_00_2 = {49 4f 4d 41 43 41 64 64 72 65 73 73 } //1 IOMACAddress
		$a_00_3 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //1 IOPlatformUUID
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}