
rule Trojan_BAT_Nanocore_ZQWF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ZQWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 6f ?? ?? ?? 0a 00 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 16 13 05 2b 00 16 13 06 2b 00 16 13 07 2b 00 16 13 08 2b 00 16 13 09 2b 00 16 13 0a 2b 00 16 13 0b 2b 00 16 13 0c 2b 00 11 04 28 ?? ?? ?? 06 74 36 00 00 01 6f ?? ?? ?? 0a 17 9a 80 02 00 00 04 23 66 66 66 66 66 66 28 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}