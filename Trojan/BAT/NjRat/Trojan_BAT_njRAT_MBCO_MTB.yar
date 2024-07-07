
rule Trojan_BAT_njRAT_MBCO_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 04 46 04 46 04 56 04 56 04 4b 04 41 04 3a 04 4f 04 56 04 56 04 46 04 3e 04 4b 04 36 04 30 04 32 04 56 04 4b 04 4b 04 56 04 45 04 3b 04 34 04 4b 04 } //1 ыццііыскяііцоыжавіыыіхлды
		$a_01_1 = {50 00 76 00 37 00 46 00 32 00 70 00 55 00 73 00 44 00 45 00 6d 00 72 00 77 00 75 00 6b 00 53 00 48 00 72 00 49 00 52 00 71 00 69 00 56 00 49 00 76 00 66 00 7a 00 6b 00 4e 00 33 00 4f 00 39 00 51 00 4b 00 65 00 56 00 4c 00 41 00 68 00 78 00 } //1 Pv7F2pUsDEmrwukSHrIRqiVIvfzkN3O9QKeVLAhx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}