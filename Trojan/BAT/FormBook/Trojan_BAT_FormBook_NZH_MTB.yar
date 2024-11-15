
rule Trojan_BAT_FormBook_NZH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {36 37 35 32 38 32 61 63 2d 61 33 34 35 2d 34 39 31 62 2d 39 32 39 32 2d 66 31 65 35 34 64 31 37 63 31 63 63 } //3 675282ac-a345-491b-9292-f1e54d17c1cc
		$a_01_1 = {00 06 07 72 3d 04 00 70 03 07 18 5a } //1
		$a_01_2 = {1a 62 72 3d 04 00 70 03 07 18 5a 17 58 } //1
		$a_81_3 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_81_4 = {43 75 73 74 6f 6d 44 65 63 6f 64 65 } //1 CustomDecode
	condition:
		((#a_81_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}