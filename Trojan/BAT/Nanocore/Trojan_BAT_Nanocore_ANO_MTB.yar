
rule Trojan_BAT_Nanocore_ANO_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 17 07 09 09 d2 9c 08 09 06 09 06 16 6f ?? ?? ?? 0a 5d 91 9c 09 17 58 0d 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Nanocore_ANO_MTB_2{
	meta:
		description = "Trojan:BAT/Nanocore.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0b 2b 49 16 0c 2b 2c 09 07 08 6f ?? 00 00 0a 26 09 07 08 6f ?? 00 00 0a 13 08 11 08 28 ?? 00 00 0a 13 09 11 05 11 04 11 09 28 ?? 00 00 0a 9c 08 17 58 0c 08 09 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Nanocore_ANO_MTB_3{
	meta:
		description = "Trojan:BAT/Nanocore.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0e 02 03 06 04 05 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 09 04 6f ?? 00 00 0a 05 32 e0 } //3
		$a_03_1 = {16 0a 2b 0d 02 06 03 04 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 e1 } //2
		$a_01_2 = {54 00 65 00 6d 00 70 00 65 00 72 00 61 00 74 00 75 00 72 00 65 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 } //1 TemperatureConverter
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}