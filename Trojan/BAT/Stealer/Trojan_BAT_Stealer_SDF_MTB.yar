
rule Trojan_BAT_Stealer_SDF_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 07 6f 90 01 03 0a 07 6f 90 01 03 0a 6f 90 01 03 0a 04 16 04 8e 69 6f 90 01 03 0a 10 02 04 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}