
rule Trojan_BAT_Convagent_MK_MTB{
	meta:
		description = "Trojan:BAT/Convagent.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 0a 16 9a 0a 72 01 00 00 70 72 0d 00 00 70 06 72 0d 00 00 70 28 0c 00 00 0a 28 0d 00 00 0a 26 00 de 21 0b 00 72 11 00 00 70 07 6f 0e 00 00 0a 28 0f 00 00 0a 28 10 00 00 0a 00 28 11 00 00 0a 26 00 de } //20
		$a_01_1 = {6f 62 6a 5c 44 65 62 75 67 5c 53 69 6c 65 6e 74 52 75 6e 6e 65 72 } //15 obj\Debug\SilentRunner
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}