
rule Trojan_BAT_Dropper_ZEGA_MTB{
	meta:
		description = "Trojan:BAT/Dropper.ZEGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 70 00 00 0a 0b 00 07 1f 10 8d 40 00 00 01 0c 08 16 17 9c 08 17 18 9c 08 18 19 9c 08 19 1a 9c 08 1a 1b 9c 08 1b 1c 9c 08 1c 1d 9c 08 1d 1e 9c 08 1e 1f 09 9c 08 1f 09 17 9c 08 1f 0a 18 9c 08 1f 0b 19 9c 08 1f 0c 1a 9c 08 1f 0d 1b 9c 08 1f 0e 1c 9c 08 1f 0f 1d 9c 08 6f 90 01 03 0a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}