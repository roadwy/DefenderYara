
rule Trojan_BAT_AsyncRat_CLP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b 11 0c 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 11 07 07 6e 11 0c 6a 58 1a 6a 5d d4 91 61 d2 81 ?? ?? ?? ?? 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}