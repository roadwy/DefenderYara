
rule Trojan_BAT_Dorifel_SP_MTB{
	meta:
		description = "Trojan:BAT/Dorifel.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 8e b7 18 da 16 da 17 d6 6b 28 3b 00 00 0a 5a 28 3c 00 00 0a 22 00 00 80 3f 58 6b 6c 28 3d 00 00 0a b7 13 04 08 06 11 04 93 6f 3e 00 00 0a 26 09 17 d6 0d 09 11 05 31 c2 } //2
		$a_01_1 = {74 6d 70 39 34 38 32 2e 74 6d 70 2e 65 78 65 } //1 tmp9482.tmp.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}