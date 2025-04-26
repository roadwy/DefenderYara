
rule Trojan_BAT_XWorm_PTL_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 13 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 28 10 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}