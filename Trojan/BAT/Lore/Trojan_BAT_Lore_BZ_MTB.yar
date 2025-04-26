
rule Trojan_BAT_Lore_BZ_MTB{
	meta:
		description = "Trojan:BAT/Lore.BZ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 68 65 75 72 65 75 78 00 49 6d 61 67 69 6e 65 72 } //1
		$a_01_1 = {65 00 78 00 61 00 67 00 e8 00 72 00 65 00 2e 00 64 00 6c 00 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}