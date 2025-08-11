
rule Trojan_BAT_FormBook_VNT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.VNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 09 6f ?? 00 00 0a 13 0a 11 06 11 05 6f ?? 00 00 0a 59 13 0b 11 0b 19 32 3d 19 8d 63 00 00 01 25 16 12 0a 28 ?? 00 00 0a 9c 25 17 12 0a 28 ?? 00 00 0a 9c 25 18 12 0a 28 ?? 00 00 0a 9c 13 0c 08 72 9b 0f 00 70 28 ?? 00 00 0a 26 11 05 11 0c ?? ?? 00 00 0a 2b 48 11 0b 16 31 43 19 8d 63 00 00 01 25 16 12 0a 28 8d 00 00 0a 9c 25 17 12 0a 28 8e 00 00 0a 9c 25 18 12 0a 28 8f 00 00 0a 9c 13 0d 16 13 0e 2b 12 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}