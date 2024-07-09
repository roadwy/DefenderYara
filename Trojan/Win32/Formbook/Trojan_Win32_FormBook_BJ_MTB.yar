
rule Trojan_Win32_FormBook_BJ_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 c2 0f b7 c9 [0-25] 90 13 [0-25] 46 [0-25] 8b 17 [0-20] 90 18 [0-20] 0f 6e da [0-20] 31 f2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}