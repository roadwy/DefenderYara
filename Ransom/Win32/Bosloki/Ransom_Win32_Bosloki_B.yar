
rule Ransom_Win32_Bosloki_B{
	meta:
		description = "Ransom:Win32/Bosloki.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c0 53 33 d2 90 01 01 8d 0c 02 8a 09 90 01 02 80 f1 ad 8d 1c 02 88 0b 42 81 fa 90 01 04 75 90 01 01 05 90 01 04 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}