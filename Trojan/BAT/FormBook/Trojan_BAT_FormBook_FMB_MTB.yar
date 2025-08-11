
rule Trojan_BAT_FormBook_FMB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe 15 27 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d c9 01 00 04 12 01 12 00 28 ?? 00 00 0a 7d ca 01 00 04 12 01 12 00 28 ?? 00 00 0a 7d cb 01 00 04 0e 05 0d 09 39 9b 00 00 00 00 23 89 41 60 e5 d0 22 d3 3f 07 7b c9 01 00 04 6c 5a 23 62 10 58 39 b4 c8 e2 3f 07 7b ca 01 00 04 6c 5a 58 23 c9 76 be 9f 1a 2f bd 3f 07 7b cb 01 00 04 6c 5a 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}