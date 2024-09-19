
rule Trojan_BAT_Dacic_ARA_MTB{
	meta:
		description = "Trojan:BAT/Dacic.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 11 09 fe 02 16 fe 01 13 0a 11 0a 2c 0c 00 08 09 6f ?? ?? ?? 0a 00 00 2b 2a 00 11 09 08 6f ?? ?? ?? 0a 59 13 0b 11 0b 16 fe 02 13 0c 11 0c 2c 12 00 08 09 16 11 0b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 00 09 6f ?? ?? ?? 0a 00 11 07 17 58 13 07 00 11 07 07 6f ?? ?? ?? 0a fe 04 13 0d 11 0d 3a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}