
rule Trojan_MacOS_Amos_CT_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CT!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 53 48 81 ec c8 00 00 00 48 8d 35 5c 07 00 00 48 8d 7d 98 e8 1c 04 00 00 48 8d 35 8d 07 00 00 48 8d bd 38 ff ff ff e8 09 04 00 00 48 8d 35 2f cb 00 00 48 8d bd 50 ff ff ff e8 f6 03 00 00 48 8d bd 68 ff ff ff 48 8d b5 38 ff ff ff e8 86 fe ff ff 48 8d 7d b0 48 8d b5 68 ff ff ff 48 8d 55 98 e8 37 fd ff ff 48 8d 7d 80 48 8d b5 50 ff ff ff e8 62 fe ff ff 48 8d 7d c8 48 8d 75 80 48 8d 55 98 e8 16 fd ff ff f6 45 c8 01 74 06 48 8b 7d d8 eb 04 } //1
		$a_00_1 = {4c 89 f0 48 83 e0 f8 48 83 c0 08 4d 89 f4 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 1b 01 00 00 48 89 43 10 49 83 cc 01 4c 89 23 4c 89 73 08 48 89 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}