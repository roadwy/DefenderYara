
rule Trojan_Win32_FormBook_BK_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 34 0a f8 [0-30] 31 3c 24 [0-30] 8f 04 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}