
rule Trojan_Win32_Astaroth_psyW_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {76 13 8b 55 f4 2b d0 89 4d fc 8a 0c 02 88 08 40 ff 4d fc 75 f5 56 } //00 00 
	condition:
		any of ($a_*)
 
}