
rule Trojan_BAT_Remcos_ZHE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 3d 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 02 } //6
		$a_03_1 = {08 1f 28 5d 1b 58 13 0a 02 08 11 07 6f ?? 00 00 0a 13 0b 04 03 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}