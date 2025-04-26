
rule Trojan_Win32_Zenpak_GPE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 1a 8b 55 ?? 32 0c 32 8b 75 ?? 88 0c 1e 8b } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}