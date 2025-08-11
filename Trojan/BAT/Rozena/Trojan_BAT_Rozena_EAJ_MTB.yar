
rule Trojan_BAT_Rozena_EAJ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.EAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 02 07 02 8e 69 5d 91 58 06 07 91 58 20 ff 00 00 00 5f 0c 06 07 08 28 04 00 00 06 07 17 58 0b 07 20 00 01 00 00 32 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}