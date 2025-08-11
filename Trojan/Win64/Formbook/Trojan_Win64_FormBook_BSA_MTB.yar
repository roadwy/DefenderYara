
rule Trojan_Win64_FormBook_BSA_MTB{
	meta:
		description = "Trojan:Win64/FormBook.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 59 46 35 6a 4f 36 49 37 78 54 70 79 39 68 39 4f 30 63 4f 55 47 6e 4c 76 32 2e 64 6c 6c } //1 aYF5jO6I7xTpy9h9O0cOUGnLv2.dll
		$a_01_1 = {30 4d 78 52 55 35 33 67 37 63 54 54 39 4a 6a 53 75 46 69 52 36 78 35 46 55 68 } //1 0MxRU53g7cTT9JjSuFiR6x5FUh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}