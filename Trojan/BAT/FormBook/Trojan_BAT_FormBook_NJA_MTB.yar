
rule Trojan_BAT_FormBook_NJA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {34 42 31 45 38 41 45 36 2d 30 39 43 38 2d 34 34 38 30 2d 38 33 39 39 2d 33 44 31 37 34 30 45 41 45 32 37 37 } //2 4B1E8AE6-09C8-4480-8399-3D1740EAE277
		$a_01_1 = {11 0c 25 17 58 13 0c 93 11 05 61 60 13 07 11 0f 1f 22 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}