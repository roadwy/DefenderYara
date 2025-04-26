
rule Trojan_BAT_Remcos_SXDA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SXDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 06 } //2
		$a_03_1 = {08 11 06 58 1f 64 5d 13 07 11 07 1f 1e 32 14 11 07 1f 46 32 07 72 1b 01 00 70 2b 0c 72 25 01 00 70 2b 05 72 2f 01 00 70 13 08 02 08 11 06 6f ?? 00 00 0a 13 09 04 03 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}