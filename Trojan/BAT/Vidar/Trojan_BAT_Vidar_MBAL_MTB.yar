
rule Trojan_BAT_Vidar_MBAL_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MBAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 0a 2b 14 00 02 7b ?? 00 00 04 06 06 73 ?? 00 00 06 a2 00 06 17 58 0a 06 7e ?? 00 00 04 17 58 fe 04 0b 07 2d de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}