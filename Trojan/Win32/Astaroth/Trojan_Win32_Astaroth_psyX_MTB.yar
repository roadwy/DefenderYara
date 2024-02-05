
rule Trojan_Win32_Astaroth_psyX_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {68 65 28 40 00 68 3d 28 40 00 6a 00 e8 09 20 00 00 c3 6a 00 68 70 28 40 00 68 85 03 00 00 68 00 20 40 00 ff 35 74 28 40 00 e8 da 1f 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}