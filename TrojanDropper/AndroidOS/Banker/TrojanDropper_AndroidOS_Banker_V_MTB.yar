
rule TrojanDropper_AndroidOS_Banker_V_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {35 10 23 00 48 06 02 00 d0 58 d4 6c dc 09 00 03 48 09 07 09 14 0a d2 ed 0c 00 93 0a 08 0a b1 5a 97 05 06 09 8d 55 4f 05 04 00 14 05 21 3c 4d 00 14 06 23 8c 27 00 92 0a 0a 05 b1 8a 90 05 0a 06 d8 00 00 01 28 de } //05 00 
		$a_00_1 = {35 02 26 00 d8 05 05 18 48 03 01 02 d0 58 24 fa dc 09 02 02 48 09 06 09 14 0a f3 ec 05 00 b0 8a b0 a5 b7 93 8d 33 4f 03 04 02 14 03 31 1f 04 00 14 09 9b 4e 08 00 90 0a 05 08 b1 3a 90 03 0a 09 d8 02 02 01 01 8b 01 38 01 b3 28 db } //00 00 
	condition:
		any of ($a_*)
 
}