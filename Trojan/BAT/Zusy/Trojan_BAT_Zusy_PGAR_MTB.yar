
rule Trojan_BAT_Zusy_PGAR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PGAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 16 11 04 08 8e 69 09 8e 69 28 0c 00 00 0a 00 28 0d 00 00 0a 72 93 01 00 70 07 1f 64 20 e7 03 00 00 6f 0e 00 00 0a 8c 05 00 00 01 72 af 01 00 70 28 0f 00 00 0a 28 10 00 00 0a 13 05 11 05 11 04 } //5
		$a_01_1 = {28 11 00 00 0a 00 72 b9 01 00 70 11 05 28 04 00 00 0a 00 72 fd 01 00 70 28 03 00 00 0a 00 11 05 28 12 00 00 0a 26 00 de 05 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}