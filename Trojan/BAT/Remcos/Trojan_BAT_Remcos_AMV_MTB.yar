
rule Trojan_BAT_Remcos_AMV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 04 28 ?? 00 00 2b 05 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 07 03 28 ?? 00 00 2b 16 03 28 ?? 00 00 2b 6f ?? 00 00 0a 0c de 14 } //4
		$a_80_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}