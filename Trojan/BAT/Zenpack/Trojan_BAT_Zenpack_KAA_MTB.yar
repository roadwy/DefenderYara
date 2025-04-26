
rule Trojan_BAT_Zenpack_KAA_MTB{
	meta:
		description = "Trojan:BAT/Zenpack.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 58 49 11 04 46 61 52 16 28 ?? 00 00 06 26 06 17 58 0a 06 } //1
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}