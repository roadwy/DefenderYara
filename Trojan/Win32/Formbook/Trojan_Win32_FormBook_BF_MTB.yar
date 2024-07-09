
rule Trojan_Win32_FormBook_BF_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8f 04 31 d9 [0-30] 90 13 8b 04 32 [0-30] bf [0-30] 31 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}