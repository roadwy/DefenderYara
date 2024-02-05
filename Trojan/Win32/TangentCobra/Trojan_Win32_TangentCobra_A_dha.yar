
rule Trojan_Win32_TangentCobra_A_dha{
	meta:
		description = "Trojan:Win32/TangentCobra.A!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 0f b6 14 04 41 ff c0 03 d7 0f b6 ca 8a 14 0c 43 32 14 13 41 88 12 49 ff c2 49 ff c9 } //00 00 
	condition:
		any of ($a_*)
 
}