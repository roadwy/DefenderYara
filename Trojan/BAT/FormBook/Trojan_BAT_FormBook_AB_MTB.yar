
rule Trojan_BAT_FormBook_AB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 83 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 07 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_BAT_FormBook_AB_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 09 00 00 fe 0c 01 00 6f ?? ?? ?? 0a 20 a0 5c bb 56 fe 0c 04 00 59 61 fe 0e 02 00 fe 0c 00 00 fe 0c 02 00 20 ?? ?? ?? 56 fe 0c 04 00 61 61 fe 09 01 00 fe 0c 01 00 fe 09 01 00 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 fe 0e 03 00 fe 0d 03 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 00 00 fe 0c 01 00 20 ?? ?? ?? 56 fe 0c 04 00 61 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 6f ?? ?? ?? 0a 3f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}