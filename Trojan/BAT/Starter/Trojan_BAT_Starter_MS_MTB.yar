
rule Trojan_BAT_Starter_MS_MTB{
	meta:
		description = "Trojan:BAT/Starter.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {1f 0b 11 0b a2 28 90 01 0e 6f 90 01 04 13 0c 11 0c 72 90 01 04 6f 90 01 04 13 0d 11 0d 72 90 01 04 6f 90 01 04 13 0e 73 90 01 04 13 0f 11 0e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}