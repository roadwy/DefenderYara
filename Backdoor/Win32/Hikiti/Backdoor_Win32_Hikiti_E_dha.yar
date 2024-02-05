
rule Backdoor_Win32_Hikiti_E_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_03_0 = {8a 10 84 d2 75 04 40 c2 04 00 8a ca 53 32 ca 88 08 40 33 c9 8a 1c 01 32 da 88 1c 01 74 09 41 81 f9 90 01 02 00 00 7c ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}