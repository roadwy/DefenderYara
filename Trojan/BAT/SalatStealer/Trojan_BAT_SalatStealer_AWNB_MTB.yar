
rule Trojan_BAT_SalatStealer_AWNB_MTB{
	meta:
		description = "Trojan:BAT/SalatStealer.AWNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 2c 04 02 8e 2d 06 7e ?? 00 00 0a 2a 03 2d 0c 28 ?? 00 00 0a 02 6f ?? 00 00 0a 2a 02 8e 69 8d ?? 00 00 01 0a 16 0b 2b 0d 06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed 28 ?? 00 00 0a 06 6f ?? 00 00 0a 2a } //5
		$a_03_1 = {06 18 5d 2d 07 28 ?? 00 00 06 2b 05 28 ?? 00 00 06 1f 64 07 1f 32 5a 58 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 07 19 32 d5 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}