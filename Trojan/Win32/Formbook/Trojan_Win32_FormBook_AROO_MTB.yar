
rule Trojan_Win32_FormBook_AROO_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AROO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f0 f7 e1 d1 ea 83 e2 ?? 8d 04 52 f7 d8 8a 84 06 ?? ?? ?? ?? 30 04 33 46 39 f7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}