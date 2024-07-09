
rule Trojan_Win32_Zenpak_GPB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 8b 75 ?? 32 1c 3e 8b 7d ?? 88 1c 0f c7 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}