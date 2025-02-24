
rule Trojan_BAT_Remcos_PLIHH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PLIHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 2a } //6
		$a_03_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 2a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}