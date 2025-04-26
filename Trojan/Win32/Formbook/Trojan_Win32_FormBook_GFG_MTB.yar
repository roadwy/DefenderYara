
rule Trojan_Win32_FormBook_GFG_MTB{
	meta:
		description = "Trojan:Win32/FormBook.GFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 5c 04 7d fe c0 04 01 04 ca 34 72 fe c0 04 82 04 7f 34 7f 2c 92 34 62 2c 08 fe c0 04 4f fe c0 88 84 0d ?? ?? ?? ?? 83 c1 ?? eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}