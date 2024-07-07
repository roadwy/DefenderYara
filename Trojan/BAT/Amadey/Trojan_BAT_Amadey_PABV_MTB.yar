
rule Trojan_BAT_Amadey_PABV_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 2f 00 20 01 00 00 00 20 a9 00 00 00 20 2a 00 00 00 58 9c 20 bf 00 00 00 38 08 2a 00 00 fe 0c 07 00 20 07 00 00 00 fe 0c 00 00 9c 20 4f 00 00 00 38 e8 29 } //1
		$a_01_1 = {11 1d 11 30 19 58 11 19 20 00 00 00 ff 5f 1f 18 64 d2 9c 20 75 00 00 00 38 37 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}