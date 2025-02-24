
rule Trojan_BAT_RedLineStealer_PQBH_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.PQBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {39 00 00 0a 0a 06 72 ?? 00 00 70 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 06 72 ?? 00 00 70 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 0b 14 0c 38 12 00 00 00 00 28 ?? ?? ?? ?? 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2c eb 07 08 16 08 8e 69 6f ?? ?? ?? ?? 0d dd } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}