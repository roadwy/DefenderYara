
rule Trojan_BAT_Vidar_MBN_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0c 08 06 7d ?? 00 00 04 00 07 7e ?? 00 00 04 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 08 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}