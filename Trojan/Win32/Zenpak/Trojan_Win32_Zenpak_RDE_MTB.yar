
rule Trojan_Win32_Zenpak_RDE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 0e 8b 75 e0 32 1c 3e 8b 7d e4 88 1c 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}