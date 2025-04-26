
rule Trojan_BAT_FormBook_NME_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 33 37 37 39 37 32 41 2d 45 41 38 36 2d 34 37 46 45 2d 38 42 46 30 2d 30 33 43 35 34 31 42 41 38 35 35 44 } //1 4377972A-EA86-47FE-8BF0-03C541BA855D
		$a_01_1 = {11 0c 11 07 58 11 09 59 93 61 11 0b } //2
		$a_01_2 = {25 06 93 0b 06 18 58 93 07 61 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}