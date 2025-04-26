
rule Trojan_BAT_Heracles_ASGC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ASGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 06 20 b0 01 00 00 93 20 78 a4 00 00 59 2b e9 11 07 20 c0 00 00 00 91 1f 69 59 2b dc 1e 0b 11 07 20 c8 00 00 00 91 13 05 } //1
		$a_01_1 = {93 05 58 1f 6d 5f 9d 61 1f 11 59 06 61 } //1
		$a_01_2 = {52 46 65 62 42 61 43 6c 68 45 57 49 46 76 77 78 71 55 } //1 RFebBaClhEWIFvwxqU
		$a_01_3 = {46 30 52 4d 63 35 54 56 75 75 4a 38 56 35 6a 67 37 65 } //1 F0RMc5TVuuJ8V5jg7e
		$a_01_4 = {66 59 6a 71 37 62 30 48 52 } //1 fYjq7b0HR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}