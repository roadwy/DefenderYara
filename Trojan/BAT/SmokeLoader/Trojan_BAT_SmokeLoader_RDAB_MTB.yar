
rule Trojan_BAT_SmokeLoader_RDAB_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.RDAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 08 17 73 08 00 00 0a 13 03 20 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}