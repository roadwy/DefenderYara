
rule Trojan_BAT_Bladabindi_RPE_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 6c 9c 06 1e 1f 61 9c 06 1f 09 1f 75 9c 06 1f 0a 1f 72 9c 06 1f 0b 1f 65 9c 06 1f 0c 1f 6e 9c 06 1f 0d 1f 74 9c 06 1f 0e 1f 70 9c 06 1f 0f 1f 72 9c 06 1f 10 1f 6f 9c 06 1f 11 1f 74 9c 06 1f 12 1f 65 9c 06 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}