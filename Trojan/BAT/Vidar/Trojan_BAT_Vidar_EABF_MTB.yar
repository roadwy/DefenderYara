
rule Trojan_BAT_Vidar_EABF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.EABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 12 03 08 02 03 08 91 08 04 28 d7 00 00 06 9c 08 17 d6 0c 08 07 31 ea } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}