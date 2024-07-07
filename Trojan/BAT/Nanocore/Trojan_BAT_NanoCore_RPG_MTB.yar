
rule Trojan_BAT_NanoCore_RPG_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 72 0e 1d 00 70 72 12 1d 00 70 6f 0d 00 00 0a 10 00 02 6f 0e 00 00 0a 18 5b 8d 0c 00 00 01 0a 16 0b 38 18 00 00 00 06 07 02 07 18 5a 18 6f 0f 00 00 0a 1f 10 28 10 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}