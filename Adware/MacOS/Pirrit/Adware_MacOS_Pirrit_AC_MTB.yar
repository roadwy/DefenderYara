
rule Adware_MacOS_Pirrit_AC_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.AC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 0d 94 1d 04 00 48 31 c1 48 89 0d 95 1d 04 00 8a 0d 8c 1d 04 00 80 f1 17 88 0d 8e 1d 04 00 8a 0d 89 1d 04 00 80 f1 bf 88 0d 8a 1d 04 00 ff 25 01 39 04 00 } //1
		$a_01_1 = {31 ff be 0a 00 00 00 e8 7c 52 03 00 48 8d 35 38 18 04 00 48 89 c7 e8 73 52 03 00 49 89 c4 31 ff be 0a 00 00 00 e8 5e 52 03 00 48 8d 35 fc 17 04 00 48 89 c7 e8 55 52 03 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}