
rule Trojan_BAT_AsyncRat_RPZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 9e 06 19 06 19 95 07 19 95 61 90 01 05 61 9e 06 1a 06 1a 95 07 1a 95 58 90 01 05 5a 9e 06 1b 06 1b 95 07 1b 95 61 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}