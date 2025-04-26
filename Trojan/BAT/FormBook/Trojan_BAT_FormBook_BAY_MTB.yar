
rule Trojan_BAT_FormBook_BAY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d 0c 15 2c 09 2b 75 17 3a ?? 00 00 00 26 1c 2c 3c 38 ?? 00 00 00 38 7b 00 00 00 38 ?? 00 00 00 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 2b 73 38 ?? 00 00 00 38 ?? 00 00 00 1f 10 8d 47 00 00 01 25 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}