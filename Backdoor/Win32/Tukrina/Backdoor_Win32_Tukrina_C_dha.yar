
rule Backdoor_Win32_Tukrina_C_dha{
	meta:
		description = "Backdoor:Win32/Tukrina.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_41_0 = {59 a9 33 76 01 } //00 05 
		$a_68_1 = {97 16 9c 01 00 05 41 68 8d 00 d2 17 01 00 05 41 68 5f 95 90 f4 01 00 05 41 68 62 62 db 68 00 00 5d 04 00 00 5c f9 03 80 5c 25 00 00 5d f9 03 80 00 00 01 00 06 00 0f 00 84 21 54 75 6b 72 69 6e 61 } //2e 44 
	condition:
		any of ($a_*)
 
}