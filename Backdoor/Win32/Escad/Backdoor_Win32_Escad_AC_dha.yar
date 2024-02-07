
rule Backdoor_Win32_Escad_AC_dha{
	meta:
		description = "Backdoor:Win32/Escad.AC!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 53 52 43 5f 48 54 4d 4c } //02 00  RSRC_HTML
		$a_01_1 = {52 53 52 43 5f 4a 50 47 } //02 00  RSRC_JPG
		$a_01_2 = {52 53 52 43 5f 57 41 56 } //05 00  RSRC_WAV
		$a_01_3 = {8a 0c 18 80 f1 63 88 0c 18 8b 4d 00 40 3b c1 72 ef } //00 00 
		$a_00_4 = {5d 04 00 00 8e 6a 03 } //80 5c 
	condition:
		any of ($a_*)
 
}