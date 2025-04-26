
rule Trojan_BAT_FormBook_BI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 3d 04 16 fe 02 0c 08 2c 35 00 19 8d ?? 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 0d 02 09 04 28 } //2
		$a_03_1 = {04 19 fe 04 16 fe 01 0a 06 2c 53 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 02 07 1f 10 63 20 ff 00 00 00 5f d2 6f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}