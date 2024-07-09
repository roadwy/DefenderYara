
rule Trojan_BAT_FormBook_AHFX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 } //2
		$a_01_1 = {5a 00 65 00 74 00 61 00 } //1 Zeta
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}