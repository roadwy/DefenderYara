
rule Trojan_BAT_NjRAT_KAU_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 69 00 45 00 53 00 63 00 59 00 42 00 68 00 65 00 61 00 6f 00 68 00 45 00 6e 00 47 00 58 00 34 00 4a 00 } //1 SiEScYBheaohEnGX4J
		$a_01_1 = {42 00 4b 00 49 00 52 00 4a 00 78 00 67 00 47 00 46 00 35 00 71 00 69 00 45 00 53 00 63 00 5a 00 66 00 67 00 6b 00 } //1 BKIRJxgGF5qiEScZfgk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}