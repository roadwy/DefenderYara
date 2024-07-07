
rule Trojan_Win32_Emotet_RTB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 62 7a 74 66 7a 65 36 78 66 34 6e 76 6d 63 30 65 63 66 68 67 73 78 35 70 33 } //pbztfze6xf4nvmc0ecfhgsx5p3  1
		$a_80_1 = {79 6f 6f 61 69 30 77 6a 78 32 75 62 72 72 62 6e 35 76 6d 62 34 33 71 7a 62 35 71 70 } //yooai0wjx2ubrrbn5vmb43qzb5qp  1
		$a_80_2 = {72 63 39 74 76 70 63 70 73 32 78 34 64 63 79 71 65 67 7a 78 62 6e 63 71 65 68 31 6f } //rc9tvpcps2x4dcyqegzxbncqeh1o  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}