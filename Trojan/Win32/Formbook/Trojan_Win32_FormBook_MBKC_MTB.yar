
rule Trojan_Win32_FormBook_MBKC_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MBKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 41 01 f7 ef 8a 86 ?? ?? ?? ?? c0 c0 05 32 81 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 89 d0 c1 e8 1f c1 fa 02 01 c2 8d 04 52 8d 04 82 f7 d8 01 c1 41 46 75 ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}