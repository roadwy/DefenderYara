
rule Trojan_BAT_Injuke_GZAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.GZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 09 08 6f ?? 00 00 0a 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 } //2
		$a_03_1 = {11 08 02 74 ?? 00 00 1b 16 02 14 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}