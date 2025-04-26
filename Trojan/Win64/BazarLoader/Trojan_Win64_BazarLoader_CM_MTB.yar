
rule Trojan_Win64_BazarLoader_CM_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 c0 6d 4e c6 41 05 39 30 00 00 48 c1 e8 10 48 99 49 23 d0 48 03 c2 49 23 c0 48 2b c2 } //10
		$a_81_1 = {4c 49 42 52 41 52 59 2e 64 6c 6c } //3 LIBRARY.dll
		$a_81_2 = {37 63 65 33 65 38 30 31 37 33 32 36 34 65 61 31 39 62 30 35 33 30 36 62 38 36 35 65 61 64 66 39 } //3 7ce3e80173264ea19b05306b865eadf9
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}