
rule Trojan_BAT_AsyncRat_CE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 07 58 09 8e 69 5d 91 11 05 1f 0d 5a 20 ?? ?? ?? ?? 5d 61 07 11 05 19 5d 1f 1f 5f 63 61 d2 13 09 11 04 11 05 11 08 11 09 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}