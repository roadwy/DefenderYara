
rule Trojan_Win32_FormBook_CM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 00 74 11 83 7d fc 04 [0-20] c7 45 [0-20] 80 34 01 ?? ff 45 fc 41 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}