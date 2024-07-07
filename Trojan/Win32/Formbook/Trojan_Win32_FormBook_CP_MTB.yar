
rule Trojan_Win32_FormBook_CP_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 14 30 83 f9 90 01 01 75 90 01 01 33 c9 eb 90 01 01 41 40 3b c7 90 13 90 02 15 8a 91 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}