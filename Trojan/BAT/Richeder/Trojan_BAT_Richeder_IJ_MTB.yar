
rule Trojan_BAT_Richeder_IJ_MTB{
	meta:
		description = "Trojan:BAT/Richeder.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0e 17 58 1f 10 5d 08 58 13 0f 11 09 11 0e 8f 18 00 00 01 13 10 11 10 11 10 47 11 0f d2 61 d2 52 11 0e 13 07 11 07 17 58 13 0e 11 0e 11 09 8e 69 32 cd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}