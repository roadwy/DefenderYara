
rule Trojan_BAT_QuasarRAT_BAA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 03 1f 20 ?? ?? 00 00 0a 16 1f 20 ?? ?? 00 00 0a ?? ?? 00 00 0a ?? ?? 00 00 0a 06 1f 10 8d 08 00 00 01 ?? ?? 00 00 0a 06 ?? ?? 00 00 0a 0b 07 02 16 02 8e 69 ?? ?? 00 00 0a 0c de 14 07 2c 06 07 6f 08 00 00 0a dc } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}