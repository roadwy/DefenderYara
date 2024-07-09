
rule Trojan_BAT_Nanocore_ABMQ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c de 0d 26 de 00 06 17 58 0a 06 1b 32 cc 90 0a 33 00 28 ?? ?? ?? 06 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 } //3
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}