
rule Trojan_BAT_Xloader_OAW_MTB{
	meta:
		description = "Trojan:BAT/Xloader.OAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 02 8e 69 17 59 91 1f 70 61 0b 1f 0b 13 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}