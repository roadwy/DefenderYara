
rule Trojan_BAT_AsyncRat_ACY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 17 da 17 d6 8d ?? ?? ?? 01 0b 02 8e 69 17 da 0c 16 0d 2b 19 07 09 02 09 91 19 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 17 d6 0d 09 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}