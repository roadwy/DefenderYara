
rule Trojan_Win32_Zenpak_GPK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 0c 1a 8b 55 90 01 01 88 0c 1a c7 05 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}