
rule Trojan_BAT_Spynoon_AACF_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 07 6f ?? 00 00 0a 13 12 16 0d 11 05 06 9a 20 0c bd 56 0f 28 ?? 00 00 06 28 ?? 00 00 0a 13 0b 11 0b 2c 0a 12 12 28 ?? 00 00 0a 0d 2b 44 11 05 06 9a 20 14 bd 56 0f 28 ?? 00 00 06 28 ?? 00 00 0a 13 0c 11 0c 2c 0a 12 12 28 ?? 00 00 0a 0d 2b 21 11 05 06 9a 20 1c bd 56 0f 28 ?? 00 00 06 28 ?? 00 00 0a 13 0d 11 0d 2c 08 12 12 28 ?? 00 00 0a 0d 11 06 09 6f ?? 00 00 0a 08 17 58 0c 08 11 08 fe 04 13 0e 11 0e 3a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}