
rule Trojan_BAT_njRAT_MBCD_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 08 16 73 ?? 00 00 0a 13 05 11 05 09 16 09 8e b7 6f 3d 00 00 0a 26 de 0c } //1
		$a_01_1 = {61 64 30 61 39 30 66 30 2d 61 64 35 38 2d 34 65 35 62 2d 38 35 37 37 2d 31 34 63 66 34 37 30 33 64 33 64 33 } //1 ad0a90f0-ad58-4e5b-8577-14cf4703d3d3
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}