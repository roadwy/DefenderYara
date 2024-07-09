
rule Trojan_BAT_Remcos_AAR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 07 09 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 13 04 11 04 0a 2b 00 06 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_AAR_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.AAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 18 2d 03 26 2b 1a 0a 2b fb 00 72 dd 03 00 70 28 ?? ?? ?? 06 1b 2d 03 26 de 09 0a 2b fb } //1
		$a_03_1 = {1a 2d 12 26 02 28 ?? ?? ?? 2b 6f ?? ?? ?? 0a 1d 2d 06 26 2b 06 0a 2b ec 0b 2b 00 2b 16 07 6f ?? ?? ?? 0a 1c 2d 0a 26 06 08 6f ?? ?? ?? 0a 2b 03 0c 2b f4 07 6f 09 00 00 0a 2d e2 de 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}