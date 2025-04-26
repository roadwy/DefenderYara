
rule Trojan_Win32_FormBook_GV_MTB{
	meta:
		description = "Trojan:Win32/FormBook.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 81 c9 ?? ?? ?? ?? 8b 34 0a 89 34 08 81 34 08 ?? ?? ?? ?? 83 c1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}