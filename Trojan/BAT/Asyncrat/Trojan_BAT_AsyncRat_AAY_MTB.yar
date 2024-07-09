
rule Trojan_BAT_AsyncRat_AAY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 25 07 28 ?? 00 00 0a 0d 08 28 ?? 00 00 0a 06 07 28 ?? 00 00 0a 13 04 09 11 04 28 ?? 00 00 06 06 08 28 ?? 00 00 0a 13 05 11 05 28 ?? 00 00 06 11 04 73 ?? 00 00 0a 13 06 11 06 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}