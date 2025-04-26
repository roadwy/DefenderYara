
rule Trojan_BAT_FormBook_NZO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 06 17 58 0a 06 02 6f ?? 00 00 0a fe 04 13 0b 11 0b } //2
		$a_03_1 = {00 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 } //1
		$a_81_2 = {36 62 65 62 64 35 61 63 2d 61 37 32 63 2d 34 34 62 38 2d 61 37 64 39 2d 66 30 31 63 32 61 65 37 35 36 33 35 } //1 6bebd5ac-a72c-44b8-a7d9-f01c2ae75635
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}