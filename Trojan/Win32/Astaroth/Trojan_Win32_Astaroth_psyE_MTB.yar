
rule Trojan_Win32_Astaroth_psyE_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {c1 e0 0c 50 59 50 ad 2b c8 03 f1 8b c8 57 51 49 8a 44 39 06 88 04 31 75 f6 } //00 00 
	condition:
		any of ($a_*)
 
}