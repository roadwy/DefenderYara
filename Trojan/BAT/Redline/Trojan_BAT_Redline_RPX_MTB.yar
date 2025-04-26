
rule Trojan_BAT_Redline_RPX_MTB{
	meta:
		description = "Trojan:BAT/Redline.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 91 0d 08 1e 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 ?? ?? ?? ?? ?? 9c 08 17 d6 0c 08 07 31 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}