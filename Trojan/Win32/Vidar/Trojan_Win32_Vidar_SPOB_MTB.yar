
rule Trojan_Win32_Vidar_SPOB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 30 8a 44 34 34 59 8b 4c 24 24 30 04 0a 41 89 4c 24 24 3b 0f 7c 8e } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}