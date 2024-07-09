
rule Trojan_BAT_AsyncRat_AAAO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AAAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 18 58 1e 58 1f 0a 59 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1e 58 1f 0a 59 91 61 28 ?? ?? 00 06 03 08 20 87 10 00 00 58 20 86 10 00 00 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}