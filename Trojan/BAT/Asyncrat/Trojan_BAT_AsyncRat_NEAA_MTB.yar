
rule Trojan_BAT_AsyncRat_NEAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 09 00 00 06 06 fe 06 18 00 00 06 73 18 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}