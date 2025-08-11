
rule Trojan_BAT_AsyncRat_ADQA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ADQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 20 aa 00 00 00 0c 16 13 04 2b 14 07 11 04 8f 15 00 00 01 25 47 08 61 d2 52 11 04 17 58 13 04 11 04 07 8e 69 32 e5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}