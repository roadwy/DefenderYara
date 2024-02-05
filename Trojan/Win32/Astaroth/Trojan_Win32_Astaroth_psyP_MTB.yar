
rule Trojan_Win32_Astaroth_psyP_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {02 ff e0 68 d0 84 40 00 b8 30 15 40 00 ff d0 ff e0 00 00 00 07 00 00 00 75 73 65 72 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}