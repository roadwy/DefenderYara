
rule Trojan_Win32_FormBook_AG_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 90 02 10 66 0f 74 c1 90 02 10 66 0f 6e e6 90 02 10 66 0f 6e e9 90 02 10 0f 57 ec 90 02 10 66 0f 7e e9 90 02 10 39 c1 74 90 00 } //4
	condition:
		((#a_02_0  & 1)*4) >=4
 
}