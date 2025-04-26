
rule Trojan_BAT_Lokibot_KAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c } //1
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}