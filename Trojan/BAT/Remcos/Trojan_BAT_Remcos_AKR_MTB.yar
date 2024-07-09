
rule Trojan_BAT_Remcos_AKR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 6a 13 0c 2b 5c 00 09 17 58 20 ?? ?? ?? 00 5f 0d 11 04 11 06 09 95 58 20 ?? ?? ?? 00 5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 11 07 11 0c d4 07 11 0c d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ?? ?? ?? 00 5f 95 61 28 ?? ?? ?? 0a 9c 00 11 0c 17 6a 58 13 0c 11 0c 11 07 8e 69 17 59 6a fe 02 16 fe 01 13 0d 11 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}