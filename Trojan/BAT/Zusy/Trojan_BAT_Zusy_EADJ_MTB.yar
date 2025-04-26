
rule Trojan_BAT_Zusy_EADJ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EADJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 10 11 10 20 af 3d d6 9d 20 e3 65 17 3d 59 65 20 05 ab 58 e8 20 59 70 dd 5c 59 20 2d 97 86 7a 65 59 59 65 61 20 07 92 65 73 5a 25 13 0f 1f 4d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}