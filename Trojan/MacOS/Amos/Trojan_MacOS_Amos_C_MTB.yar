
rule Trojan_MacOS_Amos_C_MTB{
	meta:
		description = "Trojan:MacOS/Amos.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_00_0 = {0a 69 69 38 eb 83 40 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 55 00 f1 41 ff ff 54 68 00 00 d0 08 61 0d 91 09 3d 40 39 2a 1d 00 13 08 01 40 f9 5f 01 00 71 15 b1 89 9a e0 03 13 aa } //5
		$a_00_1 = {49 29 dc 49 ff c4 0f 84 df fe ff ff 4c 89 f7 44 89 fe 4c 89 e2 e8 b9 e4 00 00 48 85 c0 0f 84 c8 fe ff ff 49 89 c6 48 89 c7 48 8d b5 51 ff ff ff 48 89 da e8 a1 e4 00 00 85 c0 0f 84 db 00 00 00 49 ff c6 4d 89 ec 4d 29 f4 49 39 dc } //5
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5) >=5
 
}