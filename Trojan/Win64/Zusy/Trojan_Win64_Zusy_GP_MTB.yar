
rule Trojan_Win64_Zusy_GP_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 61 d4 66 41 0f db d0 66 0f 67 ca 66 0f ef c8 0f 11 09 4c 39 c1 } //1
		$a_01_1 = {48 89 da 49 89 d8 48 c1 fa 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}