
rule Trojan_BAT_EtwHook_GVA_MTB{
	meta:
		description = "Trojan:BAT/EtwHook.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 b7 0d 00 70 28 3d 00 00 06 72 21 15 00 70 28 3c 00 00 06 0b 07 02 8e 69 6a 28 66 00 00 0a 1f 40 12 00 28 3e 00 00 06 26 02 16 07 02 8e 69 28 32 00 00 0a de 0d 26 72 3d 15 00 70 28 1b 00 00 0a de 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}