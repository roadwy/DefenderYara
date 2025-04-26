
rule Trojan_BAT_XWorm_AMAA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 13 [0-1e] 08 5d 13 [0-14] 61 [0-32] 20 00 04 00 00 59 [0-28] 20 00 01 00 00 5d 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}