
rule Trojan_Win32_Autophyte_D_dha{
	meta:
		description = "Trojan:Win32/Autophyte.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {23 8a 7c 8e 90 02 06 ae 3d b4 3f 90 02 06 f2 e2 33 24 90 02 06 97 51 34 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}