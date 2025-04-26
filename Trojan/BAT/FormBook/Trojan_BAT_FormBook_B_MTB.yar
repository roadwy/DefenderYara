
rule Trojan_BAT_FormBook_B_MTB{
	meta:
		description = "Trojan:BAT/FormBook.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 1f 4c 9d 25 17 1f 6f 9d 25 18 1f 61 9d 25 19 1f 64 9d 2a } //1
		$a_00_1 = {62 65 2d 72 75 6e 2d 69 6e 20 51 4f 53 20 7a 6f 64 65 } //1 be-run-in QOS zode
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_B_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 75 0d 00 00 1b 11 07 8f 01 00 00 01 25 71 01 00 00 01 11 07 02 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 01 00 00 01 11 12 20 b6 01 00 00 91 20 c2 00 00 00 59 13 10 } //3
		$a_01_1 = {31 66 39 32 65 63 61 65 2d 61 30 65 31 2d 34 39 36 61 2d 61 36 31 30 2d 30 30 64 65 64 37 31 62 37 64 37 35 } //1 1f92ecae-a0e1-496a-a610-00ded71b7d75
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}