
rule Trojan_Win32_Vidsrs_A{
	meta:
		description = "Trojan:Win32/Vidsrs.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 ff 55 89 e5 83 ed 1c 5d 60 e8 ff ff ff ff c0 5d 83 ed 0f b9 00 00 10 00 50 89 e8 8b 00 5b e2 f8 } //01 00 
		$a_03_1 = {c6 01 68 8d 83 90 01 02 00 00 89 41 01 c6 41 05 c3 b9 44 00 00 00 31 c0 8d bd 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}