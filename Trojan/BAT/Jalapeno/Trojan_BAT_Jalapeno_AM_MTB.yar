
rule Trojan_BAT_Jalapeno_AM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 25 17 28 18 00 00 06 13 04 06 28 13 00 00 06 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f } //2
		$a_01_1 = {73 65 72 76 65 72 31 } //1 server1
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}