
rule Trojan_Win32_FormBook_CL_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d0 8b c1 c1 e8 03 89 45 08 8b c1 25 00 fe ff 1f 31 45 08 8b 46 ?? c1 6d 08 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}