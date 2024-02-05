
rule Trojan_Win32_Vundo_gen_G{
	meta:
		description = "Trojan:Win32/Vundo.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 f9 6a 04 2b c1 68 00 10 00 00 8d 70 01 56 6a 00 ff 15 90 01 03 10 8a 0f 84 c9 74 0e 66 0f be c9 66 41 66 89 08 40 40 47 75 ec 66 83 20 00 90 00 } //01 00 
		$a_01_1 = {74 07 3d 38 0c 00 00 75 1f b0 01 c3 3d 0a 1a 00 00 74 f6 } //00 00 
	condition:
		any of ($a_*)
 
}