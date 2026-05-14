
rule Trojan_BAT_Razy_BAB_MTB{
	meta:
		description = "Trojan:BAT/Razy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 33 11 34 91 11 37 11 39 1a 5a 11 36 5d 91 61 d2 13 3a 11 33 11 34 17 58 91 11 37 11 39 1a 5a 17 58 11 36 5d 91 61 d2 13 3b 11 33 11 34 18 58 91 11 37 11 39 1a 5a 18 58 11 36 5d 91 61 d2 13 3c 11 33 11 34 19 58 91 11 37 11 39 1a 5a 19 58 11 36 5d 91 61 d2 13 3d 11 38 11 39 11 3a 11 3b 1e 62 60 11 3c 1f 10 62 60 11 3d 1f 18 62 60 9e 11 34 1a 58 13 34 11 39 17 58 13 39 11 39 11 35 3f 7b ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}