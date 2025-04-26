
rule Trojan_BAT_Remcos_BN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {5d 9e 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b 16 0c 2b } //4
		$a_01_1 = {06 08 06 08 94 18 5a 1f 64 5d 9e 08 17 58 0c 08 03 32 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}