
rule Trojan_BAT_Seraph_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 11 00 11 03 91 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c } //1
		$a_01_1 = {41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 47 65 74 44 61 74 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}