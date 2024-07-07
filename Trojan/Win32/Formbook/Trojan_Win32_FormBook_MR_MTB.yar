
rule Trojan_Win32_FormBook_MR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f4 8b 45 08 01 90 01 01 0f 90 02 02 0f 90 02 02 89 90 02 02 8b 90 02 02 8b 90 02 02 01 90 01 01 0f 90 02 02 8b 90 02 02 89 90 01 01 8b 90 02 02 8b 90 02 02 01 90 01 01 31 90 01 01 89 90 01 01 88 90 01 01 8b 90 02 02 89 90 02 02 83 90 02 03 8b 90 02 02 3b 90 02 02 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}