
rule Trojan_Win32_Artave_A{
	meta:
		description = "Trojan:Win32/Artave.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 80 f4 35 da c7 45 f0 c0 3c 25 d6 c7 45 fc f8 36 57 36 c7 45 f8 59 ef c8 7f 81 6d f4 0a 8f f1 70 55 81 6d fc f8 36 57 36 } //00 00 
	condition:
		any of ($a_*)
 
}