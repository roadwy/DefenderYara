
rule Trojan_BAT_Nanobot_RSY_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.RSY!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 13 00 00 06 0a 28 04 00 00 0a 06 6f 05 00 00 0a 28 06 00 00 0a 0b 02 07 28 0b 00 00 06 0c dd 06 } //1
		$a_01_1 = {03 06 91 0c 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 3f e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}