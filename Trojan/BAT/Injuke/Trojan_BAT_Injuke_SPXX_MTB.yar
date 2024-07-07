
rule Trojan_BAT_Injuke_SPXX_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 08 28 90 01 03 0a 9c 07 08 03 08 03 8e 69 5d 91 9c 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}