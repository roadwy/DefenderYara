
rule Trojan_BAT_FormBook_BSA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 6c 61 72 6d 00 41 6c 61 72 6d 65 72 00 4f 62 6a 65 63 74 00 3c 52 75 6e } //2
		$a_81_1 = {64 63 38 33 34 31 30 66 2d 33 36 34 65 2d 34 34 31 33 2d 62 62 64 66 2d 33 31 34 38 66 65 66 32 37 38 34 32 } //4 dc83410f-364e-4413-bbdf-3148fef27842
		$a_01_2 = {73 56 63 61 2e 65 78 65 } //8 sVca.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*4+(#a_01_2  & 1)*8) >=14
 
}