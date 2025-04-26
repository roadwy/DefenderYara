
rule Trojan_Win32_FormBook_GB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 8e 69 8d ?? ?? ?? 01 0d 16 13 05 2b 1a 00 09 11 05 07 11 05 91 08 11 05 08 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}