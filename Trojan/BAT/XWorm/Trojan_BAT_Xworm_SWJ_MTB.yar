
rule Trojan_BAT_Xworm_SWJ_MTB{
	meta:
		description = "Trojan:BAT/Xworm.SWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 20 00 40 00 00 6a 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 59 28 ?? 00 00 0a 69 13 06 06 11 04 16 11 06 6f ?? 00 00 0a 13 07 16 13 08 38 29 00 00 00 00 11 04 11 08 11 04 11 08 91 7e 11 00 00 04 11 05 91 61 08 11 05 91 61 d2 9c 11 05 17 58 09 5d 13 05 00 11 08 17 58 13 08 11 08 11 07 fe 04 13 09 11 09 3a c8 ff ff ff 07 11 04 16 11 07 6f ?? 00 00 0a 00 00 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a fe 04 13 0a 11 0a 3a 73 ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}