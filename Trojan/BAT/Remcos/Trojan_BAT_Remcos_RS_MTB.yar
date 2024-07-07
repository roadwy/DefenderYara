
rule Trojan_BAT_Remcos_RS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 8f 00 00 00 38 90 00 00 00 02 8e 69 5d 7e 6d 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 d6 00 00 06 02 08 17 58 02 8e 69 5d 91 } //1
		$a_01_1 = {59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 ac 0f 00 02 8e 69 17 59 28 01 00 00 2b 02 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}