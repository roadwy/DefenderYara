
rule Trojan_Win32_FormBook_DE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 45 ff 88 45 90 01 01 8a 45 90 01 01 34 90 01 01 88 45 90 01 01 03 11 90 02 30 8a 45 90 01 01 88 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}