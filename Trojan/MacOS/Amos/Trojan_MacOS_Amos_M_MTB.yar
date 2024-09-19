
rule Trojan_MacOS_Amos_M_MTB{
	meta:
		description = "Trojan:MacOS/Amos.M!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 85 db 74 0c 48 ff cb 48 ff c7 41 8a 14 37 eb 04 31 d2 31 db 88 54 35 e5 48 ff c6 48 83 fe 03 75 de } //1
		$a_00_1 = {89 c1 83 e1 0f 8a 8c 0d 20 ff ff ff 41 30 0c 06 48 ff c0 49 39 c4 75 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}