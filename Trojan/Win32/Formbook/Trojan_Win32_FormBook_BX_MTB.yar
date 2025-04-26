
rule Trojan_Win32_FormBook_BX_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 04 02 88 45 } //1
		$a_02_1 = {33 d2 8a 55 ?? 33 c2 [0-20] 90 13 [0-10] 8b 55 ?? 88 02 [0-20] ff 45 [0-10] ff 4d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}