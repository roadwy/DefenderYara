
rule Trojan_BAT_Cobaltstrike_PSWT_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PSWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 03 00 00 01 0a 16 0b 38 13 00 00 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 3f e4 ff ff ff 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}