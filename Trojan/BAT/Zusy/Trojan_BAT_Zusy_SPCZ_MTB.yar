
rule Trojan_BAT_Zusy_SPCZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SPCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 72 01 00 00 70 6f 90 01 03 0a 0c 08 17 8d 15 00 00 01 25 16 1f 0a 9d 6f 90 01 03 0a 0d 28 90 01 03 0a 13 04 00 09 13 08 16 13 09 38 b3 00 00 00 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}