
rule Trojan_BAT_Rozena_KAI_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 11 06 91 20 ?? 00 00 00 61 d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e4 } //5
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}