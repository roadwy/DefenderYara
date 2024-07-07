
rule Trojan_Win32_Zenpak_RDI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 31 32 1c 17 8b 55 e8 88 1c 32 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}