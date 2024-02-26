
rule Trojan_BAT_FormBook_VR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.VR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 0e 11 0d 17 58 13 0f 11 0d 11 06 5d 13 10 11 0f 11 06 5d 13 11 07 11 11 91 11 0e 58 13 12 07 11 10 91 13 13 11 05 11 0d 1f 16 5d 91 13 14 11 13 11 14 61 13 15 07 11 10 11 15 11 12 59 11 0e 5d d2 9c 00 11 0d 17 58 13 0d 11 0d 11 06 fe 04 13 16 11 16 2d a4 } //00 00 
	condition:
		any of ($a_*)
 
}