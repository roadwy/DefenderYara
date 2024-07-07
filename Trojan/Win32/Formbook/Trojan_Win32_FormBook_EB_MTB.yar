
rule Trojan_Win32_FormBook_EB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe c8 fe c0 fe c0 fe c0 34 6b fe c0 2c 1c fe c0 fe c0 fe c0 34 7f 04 71 fe c0 2c 57 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_FormBook_EB_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 37 80 e2 d4 88 d4 20 c4 30 d0 08 e0 88 47 01 0f b6 47 02 88 c4 89 c2 80 f4 d5 80 e2 90 20 c4 f6 d0 24 45 08 c2 80 f2 90 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}