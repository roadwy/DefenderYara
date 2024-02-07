
rule Trojan_Win32_Delf_J_ibt{
	meta:
		description = "Trojan:Win32/Delf.J!ibt,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1a 32 1e 88 19 41 46 42 48 75 f4 } //01 00 
		$a_01_1 = {8a 0a 32 0e 8b 7d e8 88 0f ff 45 e8 46 42 48 75 ef } //01 00 
		$a_01_2 = {38 33 30 33 30 32 37 38 33 35 42 36 38 36 39 35 38 36 46 37 34 33 37 32 31 44 34 46 31 41 42 34 32 31 31 32 32 31 35 44 38 45 31 43 38 30 45 33 33 } //00 00  8303027835B6869586F743721D4F1AB42112215D8E1C80E33
	condition:
		any of ($a_*)
 
}