
rule Trojan_BAT_FormBook_AKR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 17 5f 0d 2b 60 07 18 5f 17 63 13 04 2b 3f 06 02 09 11 04 6f ?? 01 00 06 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 28 ?? 00 00 06 2c 0a 03 11 05 28 ?? 00 00 06 2b 0f 11 06 16 31 0a 03 11 05 11 06 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FormBook_AKR_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 18 00 08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db } //2
		$a_01_1 = {42 00 65 00 65 00 54 00 72 00 69 00 61 00 6c 00 } //1 BeeTrial
		$a_01_2 = {4d 00 65 00 6c 00 76 00 69 00 6e 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //1 Melvin.White
		$a_01_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 System.Reflection.Assembly
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}