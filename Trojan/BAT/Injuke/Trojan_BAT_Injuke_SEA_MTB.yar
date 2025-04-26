
rule Trojan_BAT_Injuke_SEA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 1e 7e 66 01 00 04 28 3e 04 00 06 17 8d 22 00 00 01 7e 67 01 00 04 28 42 04 00 06 28 16 00 00 06 7e 56 01 00 04 28 fe 03 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}