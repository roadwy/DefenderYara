
rule Trojan_BAT_AsyncRat_CXJK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 1f 49 58 20 ?? ?? ?? ?? 5d 13 06 11 07 09 11 06 91 58 20 ?? ?? ?? ?? 5d 13 07 09 11 06 91 13 05 09 11 06 09 11 07 91 9c 09 11 07 11 05 9c 09 11 06 91 09 11 07 91 58 20 ?? ?? ?? ?? 5d 13 09 02 11 08 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 09 11 09 91 61 d2 81 ?? ?? ?? ?? 11 08 17 58 13 08 11 08 02 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}