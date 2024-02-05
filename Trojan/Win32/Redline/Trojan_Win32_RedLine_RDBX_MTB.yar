
rule Trojan_Win32_RedLine_RDBX_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 28 01 44 24 10 8b 7c 24 18 8b c6 c1 e8 05 03 fe } //00 00 
	condition:
		any of ($a_*)
 
}