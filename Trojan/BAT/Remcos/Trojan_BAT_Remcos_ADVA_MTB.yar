
rule Trojan_BAT_Remcos_ADVA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ADVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 17 0b 18 0d 19 0d 28 ?? 00 00 0a 13 04 1a 0d 11 04 17 6f ?? 00 00 0a 1b 0d 11 04 18 6f ?? 00 00 0a 1c 0d 11 04 03 04 6f ?? 00 00 0a 13 05 1d 0d 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0a de 6d } //5
		$a_01_1 = {46 00 6a 00 44 00 79 00 44 00 36 00 55 00 } //2 FjDyD6U
		$a_01_2 = {43 52 45 41 54 45 44 45 43 52 59 50 54 4f 52 } //1 CREATEDECRYPTOR
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}