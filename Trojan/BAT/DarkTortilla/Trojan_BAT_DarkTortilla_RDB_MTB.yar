
rule Trojan_BAT_DarkTortilla_RDB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {35 38 36 37 30 61 39 61 2d 62 65 30 37 2d 34 39 36 33 2d 62 34 61 36 2d 39 61 62 30 34 34 35 39 64 36 38 66 } //1 58670a9a-be07-4963-b4a6-9ab04459d68f
		$a_01_1 = {72 38 4e 48 62 34 37 43 74 6d 30 51 39 46 65 79 35 57 54 6f 32 61 33 59 36 5a 69 70 31 } //1 r8NHb47Ctm0Q9Fey5WTo2a3Y6Zip1
		$a_01_2 = {64 39 53 31 58 6b } //1 d9S1Xk
		$a_01_3 = {6e 32 50 36 54 67 } //1 n2P6Tg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}