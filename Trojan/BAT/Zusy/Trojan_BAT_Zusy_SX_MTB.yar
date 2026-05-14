
rule Trojan_BAT_Zusy_SX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 3e 00 00 01 0a 16 0b 2b 22 02 02 8e 69 17 59 07 59 91 0c 06 07 08 20 f0 00 00 00 5f 1a 63 08 1f 0f 5f 1a 62 60 d2 9c 07 17 58 0b 07 02 8e 69 32 d8 06 2a } //30
		$a_01_1 = {02 8e 69 8d 3e 00 00 01 0a 16 0b 2b 28 02 07 91 7e 08 00 00 04 61 18 62 02 07 91 7e 08 00 00 04 61 1c 63 60 d2 0c 06 07 08 7e 08 00 00 04 61 d2 9c 07 17 58 0b 07 02 8e 69 32 d2 06 2a } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}