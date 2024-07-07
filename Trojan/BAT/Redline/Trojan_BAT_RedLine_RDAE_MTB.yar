
rule Trojan_BAT_RedLine_RDAE_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 9a 00 00 00 65 66 61 fe 09 00 00 61 d1 9d } //2
		$a_01_1 = {76 44 46 71 55 4a 35 49 5a 66 } //1 vDFqUJ5IZf
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}