
rule Trojan_BAT_Rozena_KAF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 07 11 08 91 20 ?? 00 00 00 61 d2 9c 11 08 17 58 13 08 11 08 07 8e 69 } //5
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}