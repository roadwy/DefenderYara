
rule Trojan_Win32_Swrort_AB_MTB{
	meta:
		description = "Trojan:Win32/Swrort.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 44 6a 01 6a 00 6a 00 68 1c 42 00 10 6a 00 ff 15 } //5
		$a_01_1 = {6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 8b 4d e8 51 ff 15 } //5
		$a_01_2 = {6a 00 68 00 10 00 00 68 00 30 00 10 8b 55 f8 52 8b 45 e8 50 ff 15 } //5
		$a_01_3 = {44 24 24 5b 5b 61 59 5a 51 } //1 D$$[[aYZQ
		$a_01_4 = {31 3c 31 46 31 50 31 5a 31 62 31 } //1 1<1F1P1Z1b1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}