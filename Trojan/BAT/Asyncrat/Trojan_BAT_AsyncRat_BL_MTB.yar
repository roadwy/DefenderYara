
rule Trojan_BAT_AsyncRat_BL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 2a } //2
		$a_03_1 = {2b 8e 69 6f ?? 00 00 0a 08 6f } //2
		$a_03_2 = {0a 0b 16 2d e2 73 ?? 00 00 0a 0c 08 07 17 73 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*4) >=8
 
}