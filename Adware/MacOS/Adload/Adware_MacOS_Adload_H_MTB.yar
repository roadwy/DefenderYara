
rule Adware_MacOS_Adload_H_MTB{
	meta:
		description = "Adware:MacOS/Adload.H!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 bf 01 00 00 00 45 31 f6 49 c1 e6 04 48 8b 45 80 4a 8b 3c 30 48 89 de e8 36 7d 03 00 85 c0 74 0d 45 89 fe 41 ff c7 4d 39 ee 72 dd eb 14 48 8b 45 80 4a 8b 44 30 08 48 8b 8d 68 ff ff ff 4a 89 04 e1 } //1
		$a_00_1 = {49 89 d6 49 89 ff e8 d8 79 03 00 48 89 c7 4c 89 e6 e8 4d 78 03 00 48 85 c0 74 13 48 89 c3 4c 89 ff 48 89 c6 4c 89 f2 e8 c3 79 03 00 eb 02 31 db 48 89 d8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}