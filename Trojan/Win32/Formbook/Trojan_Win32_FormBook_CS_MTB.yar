
rule Trojan_Win32_FormBook_CS_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 54 0d e4 8b 7d 9c 30 14 38 83 f9 [0-30] 33 c9 [0-20] 41 40 3b c6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}