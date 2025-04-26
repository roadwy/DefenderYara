
rule Trojan_BAT_CryptInject_MTB{
	meta:
		description = "Trojan:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 fe 0c 00 00 20 01 00 00 00 13 04 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 33 0d 20 ?? ?? ?? ?? 13 04 20 ?? ?? ?? ?? 58 00 fe 01 2c 02 2b 05 38 5e ff ff ff 28 ?? 00 00 06 de 08 26 28 ?? 00 00 06 de 00 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_CryptInject_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {08 0d 09 13 04 11 04 13 05 11 05 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 06 13 06 11 06 28 ?? 00 00 0a 13 07 11 07 6f ?? 00 00 0a 13 08 11 08 14 14 6f ?? 00 00 0a 26 17 28 ?? 00 00 0a 2b 09 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_CryptInject_MTB_3{
	meta:
		description = "Trojan:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 fe 01 2c 4c 28 ?? 00 00 0a 25 28 ?? 00 00 06 14 fe ?? ?? 00 00 06 73 ?? 00 00 0a 6f ?? 00 00 0a 20 ?? 00 00 00 13 03 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 33 0d 20 ?? ?? 00 00 13 03 20 ?? ?? ?? ?? 58 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_CryptInject_MTB_4{
	meta:
		description = "Trojan:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {02 06 28 0c 00 00 06 0c 08 72 1b 00 00 70 28 1a 00 00 0a 39 de 00 00 00 } //1
		$a_00_1 = {11 05 11 06 11 05 11 06 91 1f 1b 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 32 e4 } //1
		$a_01_2 = {4f 00 53 00 4e 00 48 00 6c 00 62 00 54 00 57 00 6e 00 49 00 6f 00 54 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 OSNHlbTWnIoT.resources
		$a_01_3 = {6d 00 65 00 51 00 54 00 49 00 4e 00 4b 00 50 00 2e 00 65 00 78 00 65 00 } //1 meQTINKP.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}