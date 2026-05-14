
rule Trojan_BAT_LummaStealer_ASQB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ASQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d ?? 00 00 01 0a 16 0b 2b 1a 06 07 02 07 91 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e0 06 2a } //4
		$a_03_1 = {0a 0b 06 8e 69 8d ?? 00 00 01 0c 16 0d 2b 13 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 28 ?? 00 00 0a 08 6f ?? 00 00 0a 2a } //3
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*3) >=7
 
}