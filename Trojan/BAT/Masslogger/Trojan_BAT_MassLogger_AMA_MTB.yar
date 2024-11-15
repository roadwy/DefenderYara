
rule Trojan_BAT_MassLogger_AMA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 28 9f 00 00 06 72 39 1a 00 70 72 3d 1a 00 70 6f b1 00 00 0a 28 5b 00 00 06 7d ad 00 00 04 06 fe 06 b0 00 00 06 73 b2 00 00 0a 6f b3 00 00 0a 0c d0 6d 00 00 01 28 3a 00 00 0a 72 43 1a 00 70 17 8d 2d 00 00 01 25 16 d0 09 00 00 1b 28 3a 00 00 0a a2 28 b4 00 00 0a 25 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}