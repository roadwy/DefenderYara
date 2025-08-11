
rule Trojan_BAT_Umbral_AB_MTB{
	meta:
		description = "Trojan:BAT/Umbral.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 61 13 1c 11 1d 02 7c 0f 00 00 04 7c 15 00 00 04 1e 58 4c 61 13 1d 11 1e 02 7c 10 00 00 04 7c 16 00 00 04 4c 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}