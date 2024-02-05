
rule Trojan_Win32_Astaroth_psyF_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {8b 7d bc b9 14 00 00 00 b8 44 00 00 00 57 ab 33 c0 ab e2 fd 8b 7d b8 } //00 00 
	condition:
		any of ($a_*)
 
}