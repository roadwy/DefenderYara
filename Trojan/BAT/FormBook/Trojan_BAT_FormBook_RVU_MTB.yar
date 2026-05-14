
rule Trojan_BAT_FormBook_RVU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 07 73 ?? 00 00 06 25 12 07 28 ?? 00 00 0a 6f ?? 00 00 06 25 12 07 28 ?? 00 00 0a 6f ?? 00 00 06 25 12 07 28 ?? 00 00 0a 6f ?? 00 00 06 13 08 11 08 } //2
		$a_81_1 = {45 38 43 35 41 39 46 33 2d 37 44 34 42 2d 34 41 32 45 2d 39 46 36 43 2d 33 42 38 41 31 44 37 45 35 46 34 43 } //1 E8C5A9F3-7D4B-4A2E-9F6C-3B8A1D7E5F4C
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}