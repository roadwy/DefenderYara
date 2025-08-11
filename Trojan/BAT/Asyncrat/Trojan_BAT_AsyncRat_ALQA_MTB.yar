
rule Trojan_BAT_AsyncRat_ALQA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ALQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 09 11 06 91 11 04 11 06 11 04 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 3f db ff ff ff } //3
		$a_03_1 = {fe 0e 07 00 fe 0c 07 00 20 01 00 00 00 40 00 00 00 00 02 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 0a 1a 06 6f ?? 00 00 0a 1a 5d 59 0b 07 1a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}