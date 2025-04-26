
rule Trojan_Win32_FormBook_GFE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.GFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 13 34 65 2c 03 2c 81 04 68 34 b9 04 25 34 56 2c 79 2c bb 34 b5 88 84 0d ?? ?? ?? ?? 83 c1 ?? eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}