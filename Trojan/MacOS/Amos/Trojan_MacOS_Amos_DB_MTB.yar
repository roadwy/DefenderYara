
rule Trojan_MacOS_Amos_DB_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 8b 77 08 8b 57 10 48 8b 4f 18 44 8b 47 20 4c 8b 4f 28 8b 3f e8 5a e4 80 00 83 f8 ff 75 0b e8 12 e3 80 00 48 63 00 48 f7 d8 } //1
		$a_01_1 = {48 83 f9 04 7d 27 48 89 4c 24 18 48 c1 e1 04 48 8b 34 01 48 8b 3c 19 48 8b 4c 08 08 48 89 f0 48 89 fb e8 d7 70 f9 ff 84 c0 75 c3 eb b9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}