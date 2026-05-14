
rule Trojan_BAT_FormBook_RVX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 09 5b 07 09 5d 6f ?? 00 00 0a 13 10 19 8d ?? 00 00 01 25 16 12 10 28 ?? 00 00 0a 9c 25 17 12 10 28 ?? 00 00 0a 9c 25 18 12 10 28 ?? 00 00 0a 9c 13 11 11 05 } //2
		$a_81_1 = {30 34 39 30 35 61 33 34 2d 32 39 62 34 2d 34 63 33 66 2d 61 38 34 39 2d 32 38 33 65 63 32 36 32 30 34 65 34 } //1 04905a34-29b4-4c3f-a849-283ec26204e4
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}