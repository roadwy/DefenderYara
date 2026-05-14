
rule Trojan_BAT_Loader_ARR_MTB{
	meta:
		description = "Trojan:BAT/Loader.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 06 18 5d 16 fe 01 0c 08 2c 07 } //10
		$a_81_1 = {73 74 61 72 74 2e 65 78 65 } //8 start.exe
		$a_81_2 = {66 72 45 5a 70 6a 52 62 } //2 frEZpjRb
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*8+(#a_81_2  & 1)*2) >=20
 
}