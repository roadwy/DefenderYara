
rule Ransom_Win32_WhisperGate_K_dha{
	meta:
		description = "Ransom:Win32/WhisperGate.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 04 90 01 04 8b 90 01 02 89 04 24 e8 90 01 04 89 45 90 01 01 c7 04 24 00 00 10 00 e8 90 01 04 89 45 90 01 01 c7 44 24 08 00 00 10 00 c7 44 24 04 cc 00 00 00 8b 45 90 01 01 89 04 24 e8 90 01 04 8b 45 90 01 01 89 44 24 0c c7 44 24 08 00 00 10 00 c7 44 24 04 01 00 00 00 8b 45 90 01 01 89 04 24 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}