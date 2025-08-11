
rule Trojan_BAT_AsyncRat_CG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 12 14 28 ?? ?? ?? ?? 9c 25 17 12 14 28 ?? ?? ?? ?? 9c 25 18 12 14 28 ?? ?? ?? ?? 9c 13 10 16 13 05 2b 11 07 11 10 11 05 91 6f ?? ?? ?? ?? 11 05 17 58 13 05 11 05 11 06 fe 04 13 11 11 11 2d e3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}