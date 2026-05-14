
rule Trojan_BAT_MonikerLoader_SU_MTB{
	meta:
		description = "Trojan:BAT/MonikerLoader.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 91 1f 4d 58 13 04 11 04 1f 78 61 13 04 07 09 11 04 d2 9c 09 17 58 0d 09 06 8e 69 32 e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}